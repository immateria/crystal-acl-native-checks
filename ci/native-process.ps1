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
    public bool OutputComplete { get; set; }
    public long DurationMilliseconds { get; set; }
    public string StdoutPath { get; set; }
    public string StderrPath { get; set; }
    public string Error { get; set; }
}

public static class AclNativeProcess {
    private sealed class Budget { public int Limited; }
    private sealed class DrainState { public string Error; }
    private static void Drain(Stream input, Stream output, int maximum, Budget budget, DrainState state) {
        try {
            var buffer = new byte[8192];
            int total = 0, count;
            while ((count = input.Read(buffer, 0, buffer.Length)) != 0) {
                int kept = Math.Min(count, maximum - total);
                if (kept > 0) output.Write(buffer, 0, kept);
                output.Flush();
                total += kept;
                if (kept < count) { Interlocked.Exchange(ref budget.Limited, 1); break; }
            }
        } catch (Exception error) {
            state.Error = error.GetType().Name + ": " + error.Message;
        }
    }
    public static AclNativeProcessResult Run(string file, string[] arguments, string cwd,
                                             string prefix, int timeoutMs, int maximum) {
        var result = new AclNativeProcessResult { FilePath = file, Arguments = arguments,
            StdoutPath = prefix + ".stdout", StderrPath = prefix + ".stderr" };
        var watch = Stopwatch.StartNew();
        var process = new Process();
        FileStream outputFile = null, errorFile = null;
        bool readersComplete = false;
        try {
            try {
                process.StartInfo = new ProcessStartInfo(file) { WorkingDirectory = cwd,
                    UseShellExecute = false, RedirectStandardOutput = true,
                    RedirectStandardError = true, CreateNoWindow = true };
                foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
                process.Start();
                var budget = new Budget();
                var outputState = new DrainState();
                var errorState = new DrainState();
                // The supervising scope owns the files. A descendant can keep
                // a pipe open, but cannot keep these diagnostic files locked.
                outputFile = new FileStream(result.StdoutPath, FileMode.Create, FileAccess.Write, FileShare.Read);
                errorFile = new FileStream(result.StderrPath, FileMode.Create, FileAccess.Write, FileShare.Read);
                Stream output = outputFile, error = errorFile;
                var stdout = Task.Run(() => Drain(process.StandardOutput.BaseStream, output, maximum, budget, outputState));
                var stderr = Task.Run(() => Drain(process.StandardError.BaseStream, error, maximum, budget, errorState));
                while (!process.WaitForExit(25)) {
                    if (Volatile.Read(ref budget.Limited) != 0 || watch.ElapsedMilliseconds >= timeoutMs) break;
                }
                result.OutputLimited = Volatile.Read(ref budget.Limited) != 0;
                result.TimedOut = !process.HasExited && !result.OutputLimited && watch.ElapsedMilliseconds >= timeoutMs;
                if (result.TimedOut || result.OutputLimited) {
                    try { process.Kill(true); } catch (InvalidOperationException) { }
                }
                if (!process.WaitForExit(1000)) result.Error = "Child did not stop within bounded cleanup";
                if (process.HasExited && !result.TimedOut && !result.OutputLimited) result.ExitCode = process.ExitCode;
                readersComplete = Task.WaitAll(new[] { stdout, stderr }, 1000);
                if (!readersComplete) {
                    result.Error = "Output did not close within bounded cleanup";
                } else if (outputState.Error != null || errorState.Error != null) {
                    result.Error = "Output drain failed: " + (outputState.Error ?? errorState.Error);
                }
                result.OutputLimited |= Volatile.Read(ref budget.Limited) != 0;
                result.OutputComplete = readersComplete && !result.TimedOut && !result.OutputLimited &&
                    outputState.Error == null && errorState.Error == null;
                if (result.OutputLimited) result.ExitCode = null;
            } catch (Exception error) {
                result.Error = error.GetType().Name + ": " + error.Message;
                try { if (!process.HasExited) process.Kill(true); } catch { }
            }
        } finally {
            // Closing an inherited pipe can itself wait for a blocked reader.
            // Release owned log files synchronously; defer pipe cleanup after
            // an incomplete drain without converting it to successful output.
            outputFile?.Dispose(); errorFile?.Dispose();
            if (readersComplete) process.Dispose();
            else Task.Run(() => { try { process.Dispose(); } catch { } });
            result.DurationMilliseconds = watch.ElapsedMilliseconds;
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
