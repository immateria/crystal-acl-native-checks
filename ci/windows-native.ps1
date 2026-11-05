[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('1.21.0', '1.22.2')][string]$CrystalVersion,
    [string]$PackageRoot = (Split-Path -Parent $PSScriptRoot)
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-process.ps1')
if (-not $IsWindows) { throw 'This driver requires a native Windows x64 host' }

$assets = @{
    '1.21.0' = @{ sha256 = '1c691057aa9b17623e021a40f569ca10ce454eae068b61bba2615893249751a7'; bytes = 51869479 }
    '1.22.2' = @{ sha256 = '0d9d7202d3fd3f95712a6137d0e5f3c866408ef65339acbb3d6c3a9dc2623fd1'; bytes = 55116878 }
}
# Crystal embeds the full source path in cache directory names. A short root
# keeps native MSVC temporary object paths within the Windows path limit.
$base = Join-Path $env:RUNNER_TEMP ('a' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $base
Write-Host "ACL_OUTPUT_ROOT $base"
if ($env:GITHUB_OUTPUT) {
    [IO.File]::AppendAllText($env:GITHUB_OUTPUT, "output-root=$base`n", [Text.UTF8Encoding]::new($false))
}
$gates = [Collections.Generic.List[object]]::new()
$failures = [Collections.Generic.List[string]]::new()
$script:receiptBytes = 0

function Save-AclJson([string]$Path, $Value) {
    $Value | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}
function Write-AclReceipt([string]$Path, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $length = (Get-Item -LiteralPath $Path).Length
    if ($length -gt 524288 -or ($script:receiptBytes + $length) -gt 4194304) {
        $failures.Add("Receipt exceeds log budget: $Name")
        Write-Host "ACL_RECEIPT_OMITTED path=$Name bytes=$length sha256=$((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant())"
        return
    }
    $value = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
    $line = $value | ConvertTo-Json -Depth 100 -Compress
    $script:receiptBytes += [Text.Encoding]::UTF8.GetByteCount($line)
    Write-Host "ACL_RECEIPT path=$Name content=$line"
}
function Write-AclLog([string]$Path, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    try { $text = [IO.File]::ReadAllText($Path) }
    catch {
        $failures.Add("Diagnostic log unavailable: $Name")
        Write-Host "ACL_LOG_UNAVAILABLE path=$Name error=$($_.Exception.Message)"
        return
    }
    Write-Host "ACL_LOG_BEGIN $Name"
    if ($text.Length -gt 65536) {
        Write-Host $text.Substring(0, 32768)
        Write-Host '[middle omitted; bounded log excerpt]'
        Write-Host $text.Substring($text.Length - 32768)
    } else { Write-Host $text }
    Write-Host "ACL_LOG_END $Name"
}
function Invoke-AclGate([string]$Name, [string]$File, [string[]]$Arguments,
                        [string]$Cwd, [double]$Seconds = 180, [string]$Marker = '') {
    $env:CRYSTAL_CACHE_DIR = Join-Path $base "k$($gates.Count)"
    $result = Invoke-AclProcess -FilePath $File -ArgumentList $Arguments -WorkingDirectory $Cwd -Prefix (Join-Path $base $Name) -TimeoutSeconds $Seconds
    $passed = $result.ExitCode -eq 0 -and -not $result.TimedOut -and -not $result.OutputLimited -and -not $result.Error
    if ($passed -and $Marker) {
        $passed = @((Get-Content -LiteralPath $result.StdoutPath) | Where-Object { $_ -ceq $Marker }).Count -eq 1
    }
    $row = @{ name = $Name; passed = $passed; process = $result; failure_scope = 'harness; no ACL result inferred' }
    $gates.Add($row)
    Save-AclJson (Join-Path $base "$Name.json") $row
    Write-AclReceipt (Join-Path $base "$Name.json") "gates/$Name.json"
    Write-AclLog $result.StdoutPath "$Name.stdout"
    Write-AclLog $result.StderrPath "$Name.stderr"
    if (-not $passed) { $failures.Add($Name) }
    return $result
}
function Get-AclHashes([string]$Root) {
    $rows = [ordered]@{}
    Get-ChildItem -LiteralPath $Root -File -Recurse | Sort-Object FullName | ForEach-Object {
        $relative = [IO.Path]::GetRelativePath($Root, $_.FullName).Replace('\', '/')
        $rows[$relative] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    return $rows
}
function Get-AclVolumeProfile([string]$VolumeRoot) {
    $volumeProfile = [ordered]@{
        state = 'Unavailable'; volume_root = $VolumeRoot; device_id = $null
        drive_type = $null; filesystem = $null; volume_name = $null; diagnostic = $null
    }
    if ($VolumeRoot -notmatch '\A[A-Za-z]:[\\/]\z') {
        $volumeProfile.diagnostic = @{ operation = 'Get-CimInstance Win32_LogicalDisk'; message = 'Path root is not a drive letter; no volume profile queried' }
        return $volumeProfile
    }
    try {
        $device = $VolumeRoot.Substring(0, 2).ToUpperInvariant()
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$device'" -ErrorAction Stop | Select-Object -First 1
        if (-not $disk) { throw 'Win32_LogicalDisk returned no matching drive' }
        $volumeProfile.state = 'Captured'
        $volumeProfile.device_id = $disk.DeviceID
        $volumeProfile.drive_type = $disk.DriveType
        $volumeProfile.filesystem = $disk.FileSystem
        $volumeProfile.volume_name = $disk.VolumeName
        if (-not $disk.FileSystem) {
            $volumeProfile.diagnostic = @{ operation = 'Get-CimInstance Win32_LogicalDisk'; message = 'Volume was observed but FileSystem was not reported' }
        }
    } catch {
        $volumeProfile.diagnostic = @{ operation = 'Get-CimInstance Win32_LogicalDisk'; message = $_.Exception.Message }
    }
    return $volumeProfile
}
function Test-AclSourceManifest([string]$Root) {
    $manifest = Join-Path $Root 'SOURCE-MANIFEST.sha256'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Missing SOURCE-MANIFEST.sha256' }
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $count = 0
    foreach ($line in Get-Content -LiteralPath $manifest) {
        if ($line -notmatch '\A([0-9a-fA-F]{64})  (.+)\z') { throw "Malformed manifest row $($count + 1)" }
        $expected = $Matches[1].ToLowerInvariant()
        $relative = $Matches[2]
        if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or $relative.Contains(':') -or $relative -match '(^|/)\.{1,2}(/|$)') {
            throw "Malformed manifest path: $relative"
        }
        foreach ($segment in $relative.Split('/')) {
            if (-not $segment -or $segment.EndsWith('.') -or $segment.EndsWith(' ')) {
                throw "Malformed manifest path: $relative"
            }
        }
        if (-not $paths.Add($relative)) { throw "Duplicate manifest path: $relative" }
        $file = Join-Path $Root $relative
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing manifest file: $relative" }
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $expected) { throw "Hash mismatch: $relative (expected $expected, observed $actual)" }
        $count++
    }
    if ($count -eq 0) { throw 'Source manifest has no files' }
    return @{ schema = 'acl-source-manifest'; version = 1; state = 'Verified'; files = $count;
        manifest_sha256 = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() }
}

try {
    $os = Get-CimInstance Win32_OperatingSystem
    $fixtureTemp = [IO.Path]::GetTempPath()
    $hostEvidence = @{
        schema = 'acl-windows-ci-host'; version = 1; requested_crystal = $CrystalVersion
        os = @{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; architecture = $os.OSArchitecture }
        powershell = $PSVersionTable.PSVersion.ToString(); process_architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        image_os = $env:ImageOS; image_version = $env:ImageVersion
        repository = $env:GITHUB_REPOSITORY; source_revision = $env:GITHUB_SHA; run_id = $env:GITHUB_RUN_ID; run_attempt = $env:GITHUB_RUN_ATTEMPT
        fixture = @{ temporary_directory = $fixtureTemp; volume = (Get-AclVolumeProfile ([IO.Path]::GetPathRoot($fixtureTemp))) }
        work = @{ build_directory = $base; source_directory = (Join-Path $base 's'); volume = (Get-AclVolumeProfile ([IO.Path]::GetPathRoot($base))) }
    }
    Save-AclJson (Join-Path $base 'host.json') $hostEvidence
    Write-AclReceipt (Join-Path $base 'host.json') 'host.json'
    $manifestEvidence = Test-AclSourceManifest $PackageRoot
    Save-AclJson (Join-Path $base 'source-manifest.json') $manifestEvidence
    Write-AclReceipt (Join-Path $base 'source-manifest.json') 'source-manifest.json'
    if ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [Runtime.InteropServices.Architecture]::X64) { throw 'Expected a native x64 process' }

    # Required by Crystal's portable Windows package; this VM is disposable.
    $devMode = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
    $null = New-Item -Path $devMode -Force
    $null = New-ItemProperty -Path $devMode -Name AllowDevelopmentWithoutDevLicense -PropertyType DWord -Value 1 -Force
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vs = Invoke-AclProcess -FilePath $vswhere -ArgumentList @('-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath') -WorkingDirectory $base -Prefix (Join-Path $base 'vswhere') -TimeoutSeconds 20
    if ($vs.ExitCode -ne 0 -or $vs.Error -or $vs.TimedOut -or $vs.OutputLimited) { throw 'vswhere did not locate the C++ toolchain' }
    $install = [IO.File]::ReadAllText($vs.StdoutPath).Trim()
    $devCmd = Join-Path $install 'Common7\Tools\VsDevCmd.bat'
    # VsDevCmd can otherwise start a telemetry descendant that outlives CMD
    # while retaining its inherited stdout/stderr pipe handles.
    $env:VSCMD_SKIP_SENDTELEMETRY = '1'
    # CMD does not parse embedded quotes using the Windows CRT rules applied by
    # ProcessStartInfo.ArgumentList. Keep command syntax inside a batch file;
    # pass only its simple filename at the process boundary.
    $environmentFile = Join-Path $base 'vs-vars.txt'
    @(
        '@echo off'
        ('call "' + $devCmd + '" -no_logo -arch=x64 -host_arch=x64')
        'if errorlevel 1 exit /b %errorlevel%'
        ('set > "' + $environmentFile + '"')
    ) | Set-Content -LiteralPath (Join-Path $base 'vs-environment.cmd') -Encoding ascii
    $dev = Invoke-AclProcess -FilePath $env:ComSpec -ArgumentList @('/d', '/c', 'vs-environment.cmd') -WorkingDirectory $base -Prefix (Join-Path $base 'vs-environment') -TimeoutSeconds 30
    Save-AclJson (Join-Path $base 'vs-environment.json') $dev
    Write-AclReceipt (Join-Path $base 'vs-environment.json') 'vs-environment.json'
    Write-AclLog $dev.StdoutPath 'vs-environment.stdout'
    Write-AclLog $dev.StderrPath 'vs-environment.stderr'
    if ($dev.ExitCode -ne 0 -or $dev.Error -or $dev.TimedOut -or $dev.OutputLimited) { throw 'VsDevCmd failed' }
    # Import but never print the full environment: hosted runners contain tokens.
    [IO.File]::ReadAllLines($environmentFile) | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process') }
    }
    [IO.File]::Delete($environmentFile)
    Save-AclJson (Join-Path $base 'toolchain.json') @{
        vs_installation = $install; vc_tools = $env:VCToolsVersion; windows_sdk = $env:WindowsSDKVersion
        linker = (Get-Command link.exe -ErrorAction Stop).Source; compiler = (Get-Command cl.exe -ErrorAction Stop).Source
        developer_mode = (Get-ItemPropertyValue -Path $devMode -Name AllowDevelopmentWithoutDevLicense)
        vs_telemetry_disabled = $env:VSCMD_SKIP_SENDTELEMETRY
    }
    Write-AclReceipt (Join-Path $base 'toolchain.json') 'toolchain.json'

    $assetName = "crystal-$CrystalVersion-windows-x86_64-msvc-unsupported.zip"
    $assetUrl = "https://github.com/crystal-lang/crystal/releases/download/$CrystalVersion/$assetName"
    $archive = Join-Path $base $assetName
    Invoke-WebRequest -Uri $assetUrl -OutFile $archive -TimeoutSec 180 -MaximumRetryCount 2
    $digest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($digest -cne $assets[$CrystalVersion].sha256 -or (Get-Item -LiteralPath $archive).Length -ne $assets[$CrystalVersion].bytes) { throw 'Official compiler archive hash/length differs from pinned asset' }
    Save-AclJson (Join-Path $base 'compiler-asset.json') @{ url = $assetUrl; sha256 = $digest; bytes = (Get-Item -LiteralPath $archive).Length; verification = 'Pinned official GitHub release asset metadata checked 2026-11-04' }
    Write-AclReceipt (Join-Path $base 'compiler-asset.json') 'compiler-asset.json'
    $compilerRoot = Join-Path $base 'c'
    Expand-Archive -LiteralPath $archive -DestinationPath $compilerRoot
    $executables = @(Get-ChildItem -LiteralPath $compilerRoot -Filter crystal.exe -File -Recurse)
    if ($executables.Count -ne 1) { throw 'Expected one compiler executable in portable archive' }
    $crystal = $executables[0].FullName
    $env:PATH = (Split-Path -Parent $crystal) + [IO.Path]::PathSeparator + $env:PATH
    Remove-Item Env:CRYSTAL_PATH -ErrorAction SilentlyContinue
    $version = Invoke-AclGate 'compiler-version' $crystal @('--version') $base 20
    if ($version.ExitCode -ne 0 -or [IO.File]::ReadAllText($version.StdoutPath) -notmatch ('(?m)^Crystal ' + [Regex]::Escape($CrystalVersion) + '(?:\s|$)')) { throw 'Compiler version does not match the selected matrix cell' }
    $stdlib = Invoke-AclGate 'compiler-stdlib' $crystal @('env', 'CRYSTAL_PATH') $base 20
    if ($stdlib.ExitCode -ne 0 -or $stdlib.Error) { throw 'Compiler standard library query failed' }

    $source = Join-Path $base 's'
    Copy-Item -LiteralPath (Join-Path $PackageRoot 'source') -Destination $source -Recurse
    $acl = Join-Path $source 'filesystem-access-control'
    $capabilities = Join-Path $source 'filesystem-capabilities'
    if (-not (Test-Path -LiteralPath (Join-Path $acl 'shard.yml')) -or -not (Test-Path -LiteralPath (Join-Path $capabilities 'shard.yml'))) { throw 'Package must contain sibling source/filesystem-access-control and source/filesystem-capabilities' }
    $env:CRYSTAL_PATH = (Join-Path $capabilities 'src') + [IO.Path]::PathSeparator + [IO.File]::ReadAllText($stdlib.StdoutPath).Trim()
    Save-AclJson (Join-Path $base 'source-before.json') (Get-AclHashes $source)

    $specs = @('access_control', 'portable_access_control', 'windows_rights', 'windows_ace_views', 'windows_observation', 'windows_descriptor', 'windows_token', 'windows_token_subject', 'windows_handle', 'windows_evaluation', 'windows_writer', 'windows_capture', 'native_acl_runner', 'windows_owner_rights') | ForEach-Object { "spec/$($_)_spec.cr" }
    $null = Invoke-AclGate 'windows-specs' $crystal (@('spec', '--error-trace') + $specs) $acl 300
    $null = Invoke-AclGate 'observation-native' $crystal @('run', 'tools/portable_acl_native.cr', '--error-trace') $acl 240 'acl-observation-native-ok'
    $null = Invoke-AclGate 'token-native' $crystal @('run', 'tools/windows_token_native.cr', '--error-trace') $acl 240 'acl-windows-token-native-ok'
    $runnerOutput = Join-Path $base 'behavior'
    $null = Invoke-AclGate 'behavior-runner' $crystal @('run', 'tools/native_acl_runner.cr', '--error-trace', '--', '--output-dir', $runnerOutput, '--compiler', $crystal) $acl 300 'native-acl-runner-ok'
    Save-AclJson (Join-Path $base 'source-after.json') (Get-AclHashes $source)
    if ((Get-FileHash -LiteralPath (Join-Path $base 'source-before.json')).Hash -cne (Get-FileHash -LiteralPath (Join-Path $base 'source-after.json')).Hash) { $failures.Add('Source changed during qualification') }
} catch {
    $failures.Add($_.Exception.Message)
    Write-Host "ACL_SETUP_ERROR $($_.Exception.Message)"
} finally {
    # Keep bounded job-log evidence even when later artifact collection fails.
    Get-ChildItem -LiteralPath $base -File -Recurse | Where-Object { $_.Extension -eq '.json' -or $_.Extension -eq '.stdout' -or $_.Extension -eq '.stderr' } | Sort-Object FullName | ForEach-Object {
        $relative = [IO.Path]::GetRelativePath($base, $_.FullName).Replace('\', '/')
        if ($relative.StartsWith('s/') -or $relative.StartsWith('c/') -or $relative -match '^k\d+/') { return }
        if ($_.Extension -eq '.json') { Write-AclReceipt $_.FullName $relative }
        elseif ($relative.StartsWith('behavior/')) {
            if ($_.Extension -eq '.stdout' -and $_.Name.StartsWith('windows.')) {
                Get-Content -LiteralPath $_.FullName | ForEach-Object { Write-Host "ACL_CASE_OBSERVATION path=$relative content=$_" }
            } else { Write-AclLog $_.FullName $relative }
        }
    }
    $summary = @{ schema = 'acl-windows-ci-result'; version = 1; crystal = $CrystalVersion; passed = $failures.Count -eq 0; gates = $gates.ToArray(); failures = $failures.ToArray(); source_revision = $env:GITHUB_SHA; receipts = 'bounded job logs; separate allowlisted artifact collection records its own outcome' }
    Save-AclJson (Join-Path $base 'result.json') $summary
    Write-AclReceipt (Join-Path $base 'result.json') 'result.json'
}
if ($failures.Count -ne 0) { exit 1 }
Write-Host 'acl-windows-ci-ok'
