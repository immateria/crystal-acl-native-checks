Set-StrictMode -Version Latest

function Test-AclEvidenceReparsePath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if (-not $parent -or $parent -ceq $current) { break }
        $current = $parent
    }
    return $false
}

function Export-AclEvidence {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$SourceRoot,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [ValidateRange(1, 1048576)][int]$MaximumFileBytes = 1048576,
        [ValidateRange(131073, 16777216)][int]$MaximumTotalBytes = 16777216
    )
    # Reserve bounded room for file hashes, omissions and collection errors.
    # Payload plus manifest can therefore never exceed the profile ceiling.
    $manifestReserveBytes = 131072
    $maximumFiles = 128
    $destination = [IO.Path]::GetFullPath($DestinationRoot)
    $source = if ($SourceRoot) { [IO.Path]::GetFullPath($SourceRoot) } else { $null }
    if ($source) {
        $relativeDestination = [IO.Path]::GetRelativePath($source, $destination).Replace('\', '/')
        if ($relativeDestination -eq '.' -or ($relativeDestination -ne '..' -and -not $relativeDestination.StartsWith('../') -and -not [IO.Path]::IsPathRooted($relativeDestination))) {
            throw 'Evidence destination must be outside the native output directory'
        }
    }
    if (Test-AclEvidenceReparsePath $destination) { throw 'Evidence destination contains a reparse path' }
    if (Test-Path -LiteralPath $destination) {
        if (-not (Test-Path -LiteralPath $destination -PathType Container) -or @(Get-ChildItem -LiteralPath $destination -Force).Count -ne 0) {
            throw 'Evidence destination must be a new or empty ordinary directory'
        }
    } else { $null = [IO.Directory]::CreateDirectory($destination) }

    $files = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[object]]::new()
    $candidates = [Collections.Generic.List[string]]::new()
    $payloadBytes = 0L
    $state = 'Complete'
    $sourceUsable = $false
    if (-not $source -or -not (Test-Path -LiteralPath $source -PathType Container)) {
        $state = 'Unavailable'
        $errors.Add(@{ reason = 'missing-output-root'; message = 'Native driver output directory is unavailable; no ACL result inferred' })
    } elseif (Test-AclEvidenceReparsePath $source) {
        $state = 'Incomplete'
        $errors.Add(@{ reason = 'reparse-path'; message = 'Native output directory contains a reparse path' })
    } else { $sourceUsable = $true }

    if ($sourceUsable) {
        # These are driver-owned routes, never a recursive upload of RUNNER_TEMP.
        # In particular, vs-vars.txt can contain runner tokens after setup fails.
        foreach ($name in @('result.json', 'host.json', 'source-manifest.json', 'toolchain.json', 'compiler-asset.json', 'source-before.json', 'source-after.json', 'vs-environment.json')) {
            if (Test-Path -LiteralPath (Join-Path $source $name)) { $candidates.Add($name) }
        }
        foreach ($gate in @('compiler-version', 'compiler-stdlib', 'windows-specs', 'observation-native', 'token-native', 'behavior-runner')) {
            foreach ($extension in @('json', 'stdout', 'stderr')) {
                $name = "$gate.$extension"
                if (Test-Path -LiteralPath (Join-Path $source $name)) { $candidates.Add($name) }
            }
        }
        foreach ($name in @('vswhere.stdout', 'vswhere.stderr', 'vs-environment.stdout', 'vs-environment.stderr')) {
            if (Test-Path -LiteralPath (Join-Path $source $name)) { $candidates.Add($name) }
        }
        $behavior = Join-Path $source 'behavior'
        if (Test-Path -LiteralPath $behavior) {
            if (Test-AclEvidenceReparsePath $behavior) {
                $errors.Add(@{ reason = 'reparse-path'; path = 'behavior'; message = 'Behavior directory contains a reparse path' })
            } elseif (-not (Test-Path -LiteralPath $behavior -PathType Container)) {
                $errors.Add(@{ reason = 'invalid-directory'; path = 'behavior'; message = 'Behavior output is not a directory' })
            } else {
                # Only immediate known receipts and log routes: behavior/c is a
                # compiler cache and the bridge executable stays on the runner.
                foreach ($name in @('host.json', 'build.json', 'source-before.json', 'source-after.json', 'cases.json', 'receipt.json', 'runner-error.json')) {
                    if (Test-Path -LiteralPath (Join-Path $behavior $name)) { $candidates.Add('behavior/' + $name) }
                }
                foreach ($prefix in @('host-os', 'host-identity', 'compiler-version', 'compiler-stdlib', 'build', 'manifest',
                                      'windows.capture-rights', 'windows.token-context', 'windows.writer-files',
                                      'windows.writer-propagation', 'windows.access-check', 'windows.restricted-token',
                                      'windows.owner-rights')) {
                    foreach ($extension in @('stdout', 'stderr')) {
                        $name = "$prefix.$extension"
                        if (Test-Path -LiteralPath (Join-Path $behavior $name)) { $candidates.Add('behavior/' + $name) }
                    }
                }
            }
        }
        if (-not (Test-Path -LiteralPath (Join-Path $source 'result.json') -PathType Leaf)) {
            $errors.Add(@{ reason = 'missing-result-receipt'; message = 'Native driver did not leave a completion receipt; no ACL result inferred' })
        }
        if ($candidates.Count -gt $maximumFiles) {
            $errors.Add(@{ reason = 'file-count-limit'; message = "Only the first $maximumFiles allowlisted evidence files can be collected"; candidates = $candidates.Count })
        }
        foreach ($relative in $candidates | Select-Object -First $maximumFiles) {
            $record = [ordered]@{ path = $relative; state = 'Omitted'; bytes = $null; sha256 = $null; reason = $null }
            $inputStream = $null
            $outputStream = $null
            $target = Join-Path $destination $relative
            try {
                $path = [IO.Path]::GetFullPath((Join-Path $source $relative))
                $within = [IO.Path]::GetRelativePath($source, $path).Replace('\', '/')
                if ($within -ne $relative -or [IO.Path]::IsPathRooted($within) -or $within.StartsWith('../')) {
                    $record.reason = 'escaped-path'
                } elseif (Test-AclEvidenceReparsePath $path) {
                    $record.reason = 'reparse-path'
                } elseif (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                    $record.reason = 'not-a-file'
                } else {
                    $inputStream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                    $length = $inputStream.Length
                    $record.bytes = $length
                    if ($length -gt $MaximumFileBytes) { $record.reason = 'file-byte-limit' }
                    elseif ($payloadBytes + $length -gt $MaximumTotalBytes - $manifestReserveBytes) { $record.reason = 'profile-byte-limit' }
                    else {
                        $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $target))
                        $outputStream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                        $buffer = [byte[]]::new(8192)
                        $copied = 0L
                        while (($count = $inputStream.Read($buffer, 0, [int][Math]::Min($buffer.Length, $MaximumFileBytes - $copied + 1))) -ne 0) {
                            if ($copied + $count -gt $MaximumFileBytes -or $payloadBytes + $copied + $count -gt $MaximumTotalBytes - $manifestReserveBytes) { throw 'Evidence grew beyond its bounded copy budget' }
                            $outputStream.Write($buffer, 0, $count)
                            $copied += $count
                        }
                        if ($copied -ne $length) { throw 'Evidence size changed during collection' }
                        $outputStream.Dispose(); $outputStream = $null
                        $record.sha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
                        $record.state = 'Copied'
                        $payloadBytes += $copied
                    }
                }
            } catch {
                $record.reason = 'read-or-copy-error'
                if ($outputStream) { $outputStream.Dispose(); $outputStream = $null }
                if (Test-Path -LiteralPath $target -PathType Leaf) { [IO.File]::Delete($target) }
            } finally {
                if ($inputStream) { $inputStream.Dispose() }
                if ($outputStream) { $outputStream.Dispose() }
            }
            $files.Add($record)
        }
    }
    if ($state -eq 'Complete' -and ($errors.Count -ne 0 -or @($files | Where-Object state -NE 'Copied').Count -ne 0)) { $state = 'Incomplete' }
    $manifest = [ordered]@{
        schema = 'acl-native-evidence-export'; version = 1; state = $state
        generated_at = [DateTime]::UtcNow.ToString('o'); source_revision = $env:GITHUB_SHA
        repository = $env:GITHUB_REPOSITORY; run_id = $env:GITHUB_RUN_ID; run_attempt = $env:GITHUB_RUN_ATTEMPT
        maximum_file_bytes = $MaximumFileBytes; maximum_total_bytes = $MaximumTotalBytes
        manifest_reserve_bytes = $manifestReserveBytes; payload_bytes = $payloadBytes
        files = $files.ToArray(); errors = $errors.ToArray()
        failure_scope = 'Evidence collection only; native receipts and ACL results remain unchanged'
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($manifest | ConvertTo-Json -Depth 20 -Compress) + "`n")
    if ($bytes.Length -gt $manifestReserveBytes) { throw 'Evidence manifest exceeded its reserved byte limit' }
    [IO.File]::WriteAllBytes((Join-Path $destination 'evidence-manifest.json'), $bytes)
    return @{ state = $state; directory = $destination; files = @($files | Where-Object state -EQ 'Copied').Count
        omitted = @($files | Where-Object state -NE 'Copied').Count; errors = $errors.Count
        bytes = $payloadBytes + $bytes.Length; maximum_bytes = $MaximumTotalBytes }
}
