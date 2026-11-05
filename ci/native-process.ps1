Set-StrictMode -Version Latest

# Drain concurrently to bounded files; never buffer an unbounded child stream.
if (-not ('AclNativeProcess' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

public sealed class AclNativeProcessResult {
    public string FilePath { get; set; }
    public string[] Arguments { get; set; }
    public int? ExitCode { get; set; }
    public bool TimedOut { get; set; }
    public bool OutputLimited { get; set; }
    public long DurationMilliseconds { get; set; }
    public string StdoutPath { get; set; }
    public string StderrPath { get; set; }
    public string Error { get; set; }
}

public static class AclNativeProcess {
    private sealed class Budget { public int Limited; }
    private static void Drain(Stream input, string path, int maximum, Budget budget) {
        using (var output = File.Create(path)) {
            var buffer = new byte[8192];
            int total = 0, count;
            while ((count = input.Read(buffer, 0, buffer.Length)) != 0) {
                int kept = Math.Min(count, maximum - total);
                if (kept > 0) output.Write(buffer, 0, kept);
                total += kept;
                if (kept < count) { Interlocked.Exchange(ref budget.Limited, 1); break; }
            }
        }
    }
    public static AclNativeProcessResult Run(string file, string[] arguments, string cwd,
                                             string prefix, int timeoutMs, int maximum) {
        var result = new AclNativeProcessResult { FilePath = file, Arguments = arguments,
            StdoutPath = prefix + ".stdout", StderrPath = prefix + ".stderr" };
        var watch = Stopwatch.StartNew();
        using (var process = new Process()) {
            try {
                process.StartInfo = new ProcessStartInfo(file) { WorkingDirectory = cwd,
                    UseShellExecute = false, RedirectStandardOutput = true,
                    RedirectStandardError = true, CreateNoWindow = true };
                foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
                process.Start();
                var budget = new Budget();
                var stdout = Task.Run(() => Drain(process.StandardOutput.BaseStream, result.StdoutPath, maximum, budget));
                var stderr = Task.Run(() => Drain(process.StandardError.BaseStream, result.StderrPath, maximum, budget));
                while (!process.WaitForExit(25)) {
                    if (Volatile.Read(ref budget.Limited) != 0 || watch.ElapsedMilliseconds >= timeoutMs) break;
                }
                result.OutputLimited = Volatile.Read(ref budget.Limited) != 0;
                result.TimedOut = !process.HasExited && !result.OutputLimited && watch.ElapsedMilliseconds >= timeoutMs;
                if (result.TimedOut || result.OutputLimited) {
                    try { process.Kill(true); } catch (InvalidOperationException) { }
                }
                if (!process.WaitForExit(1000)) result.Error = "Child did not stop within bounded cleanup";
                if (!Task.WaitAll(new[] { stdout, stderr }, 1000)) {
                    result.Error = "Output did not close within bounded cleanup";
                    process.StandardOutput.Close(); process.StandardError.Close();
                }
                result.OutputLimited |= Volatile.Read(ref budget.Limited) != 0;
                if (process.HasExited && !result.TimedOut && !result.OutputLimited) result.ExitCode = process.ExitCode;
            } catch (Exception error) {
                result.Error = error.GetType().Name + ": " + error.Message;
                try { if (!process.HasExited) process.Kill(true); } catch { }
            } finally { result.DurationMilliseconds = watch.ElapsedMilliseconds; }
        }
        return result;
    }
}
'@
}

function Invoke-AclProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string]$Prefix,
        [ValidateRange(0.01, 1200)][double]$TimeoutSeconds = 180,
        [ValidateRange(1, 4194304)][int]$MaximumBytes = 1048576
    )
    return [AclNativeProcess]::Run($FilePath, $ArgumentList, $WorkingDirectory, $Prefix,
        [int][Math]::Ceiling($TimeoutSeconds * 1000), $MaximumBytes)
}
