require "json"

module NativeACLRunner
  module Harness
    MAX_OUTPUT_BYTES = 1_048_576

    # These documented exception statuses identify an abnormal Windows helper
    # termination. Arbitrary nonzero exits and loader failures stay distinct.
    WINDOWS_EXCEPTION_STATUSES = [
      0xc0000005_u32, # STATUS_ACCESS_VIOLATION
      0xc000001d_u32, # STATUS_ILLEGAL_INSTRUCTION
      0xc0000094_u32, # STATUS_INTEGER_DIVIDE_BY_ZERO
      0xc00000fd_u32, # STATUS_STACK_OVERFLOW
      0xc0000374_u32, # STATUS_HEAP_CORRUPTION
      0xc0000409_u32, # STATUS_STACK_BUFFER_OVERRUN / fail-fast
    ]

    record Execution, command : Array(String), exit_code : Int32?, signal : String?,
      timed_out : Bool, output_limited : Bool, duration_ms : Int64,
      stdout_path : String, stderr_path : String, error : String? do
      include JSON::Serializable
    end

    private record Event, kind : Symbol, status : Process::Status? = nil, error : String? = nil

    def self.execute(command : Array(String), prefix : Path, deadline : Time::Span,
                     env : Process::Env = nil, chdir : String? = nil,
                     maximum_output : Int32 = MAX_OUTPUT_BYTES) : Execution
      started = Time.monotonic
      output_path = "#{prefix}.stdout"
      error_path = "#{prefix}.stderr"
      raise ArgumentError.new("Positive deadline and output bound required") unless deadline > Time::Span.zero && maximum_output > 0
      begin
        output_read, output_write = IO.pipe(write_blocking: true)
        error_read, error_write = IO.pipe(write_blocking: true)
        events = Channel(Event).new(8)
        process = Process.new(command[0], command[1..], env: env, chdir: chdir,
          output: output_write, error: error_write)
        output_write.close
        error_write.close
        spawn { drain(output_read, output_path, maximum_output, events, :stdout) }
        spawn { drain(error_read, error_path, maximum_output, events, :stderr) }
        spawn do
          begin
            events.send(Event.new(:exit, process.wait))
          rescue error
            events.send(Event.new(:exit, error: error.message))
          end
        end
        status = nil.as(Process::Status?)
        finished = [] of Symbol
        timed_out = false
        limited = false
        failure = nil.as(String?)
        until finished.includes?(:exit) && finished.includes?(:stdout) && finished.includes?(:stderr)
          remaining = deadline - (Time.monotonic - started)
          if remaining <= Time::Span.zero
            timed_out = true
            break
          end
          select
          when event = events.receive
            if event.kind == :limit
              limited = true
              break
            end
            finished << event.kind
            status = event.status if event.kind == :exit
            failure ||= event.error
          when timeout(remaining)
            timed_out = true
            break
          end
        end
        if timed_out || limited
          begin
            process.terminate(graceful: false)
          rescue
            # It may have exited between observing the boundary and termination.
          end
          output_read.close unless output_read.closed?
          error_read.close unless error_read.closed?
          # Bound reaping/drain completion too; descendants holding a pipe cannot
          # turn a completed parent into an unbounded harness wait.
          reap_deadline = Time.monotonic + 1.second
          until finished.includes?(:exit) && finished.includes?(:stdout) && finished.includes?(:stderr)
            remaining = reap_deadline - Time.monotonic
            break if remaining <= Time::Span.zero
            select
            when event = events.receive
              finished << event.kind
            when timeout(remaining)
              break
            end
          end
        end
        normal_code = !timed_out && !limited ? status.try(&.exit_code?) : nil
        Execution.new(command, normal_code, status.try(&.exit_signal?.try(&.to_s)),
          timed_out, limited, (Time.monotonic - started).total_milliseconds.to_i64,
          output_path, error_path, failure)
      rescue error
        Execution.new(command, nil, nil, false, false,
          (Time.monotonic - started).total_milliseconds.to_i64, output_path, error_path, error.message)
      ensure
        output_write.try { |io| io.close unless io.closed? }
        error_write.try { |io| io.close unless io.closed? }
        output_read.try { |io| io.close unless io.closed? }
        error_read.try { |io| io.close unless io.closed? }
      end
    end

    private def self.drain(input : IO, path : String, maximum : Int32,
                           events : Channel(Event), kind : Symbol) : Nil
      failure = nil.as(String?)
      File.open(path, "w") do |output|
        buffer = Bytes.new(8192)
        received = 0
        loop do
          count = input.read(buffer)
          break if count == 0
          kept = Math.min(count, maximum - received)
          output.write(buffer[0, kept]) if kept > 0
          received += kept
          if kept < count
            events.send(Event.new(:limit))
            break
          end
        end
      end
    rescue error
      failure = error.message
    ensure
      input.close unless input.closed?
      events.send(Event.new(kind, error: failure))
    end

    def self.classify(id : String, stdout : String, exit_code : Int32?, *,
                      timed_out : Bool = false, crashed : Bool = false,
                      output_limited : Bool = false, windows : Bool = false) : String
      return "timeout" if timed_out
      return "crash" if crashed || (windows && exit_code && WINDOWS_EXCEPTION_STATUSES.includes?(exit_code.to_u32!))
      return "output-limit" if output_limited
      lines = stdout.lines.reject(&.strip.empty?)
      return "incomplete" if lines.empty?
      return "malformed" unless lines.size == 1
      row = JSON.parse(lines[0])
      unless row["schema"].as_s == "filesystem-native-acl-observation" && row["version"].as_i == 1 && row["case_id"].as_s == id
        return "incomplete"
      end
      case row["harness_status"].as_s
      when "complete"
        matched = row["expectations_met"].as_bool
        violations = row["violations"].as_a
        row["observation"].as_h
        return "malformed" unless matched == violations.empty?
        return "exit-mismatch" unless exit_code == (matched ? 0 : 1)
        matched ? "matched" : "mismatch"
      when "native-error", "error"
        row["error"].as_h
        return "exit-mismatch" unless exit_code == 1
        row["harness_status"].as_s
      else
        "incomplete"
      end
    rescue JSON::ParseException | KeyError | TypeCastError
      "malformed"
    end
  end
end
