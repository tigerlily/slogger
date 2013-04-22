require 'thread'

module Slogger
  class Base
    
    #
    # Syslog Message Severities:
    #
    # - Emergency: system is unusable
    # - Alert: action must be taken immediately
    # - Critical: critical conditions
    # - Error: error conditions
    # - Warning: warning conditions
    # - Notice: normal but significant condition
    # - Informational: informational messages
    # - Debug: debug-level messages
    #
    SYSLOG_SEVERITIES = {
      :emerg   => Syslog::LOG_EMERG,
      :alert   => Syslog::LOG_ALERT,
      :crit    => Syslog::LOG_CRIT,
      :err     => Syslog::LOG_ERR,
      :warning => Syslog::LOG_WARNING,
      :notice  => Syslog::LOG_NOTICE,
      :info    => Syslog::LOG_INFO,
      :debug   => Syslog::LOG_DEBUG
    }

    #
    # Syslog Message Facilities:
    #
    # - kernel messages
    # - user-level messages
    # - mail system
    # - system daemons
    # - security/authorization messages
    # - messages generated internally by syslogd
    # - line printer subsystem
    # - network news subsystem
    # - UUCP subsystem
    # - clock daemon
    # - security/authorization messages
    # - FTP daemon
    # - NTP subsystem
    # - log audit
    # - log alert
    # - clock daemon (note 2)
    # - local use 0  (local0)
    # - local use 1  (local1)
    # - local use 2  (local2)
    # - local use 3  (local3)
    # - local use 4  (local4)
    # - local use 5  (local5)
    # - local use 6  (local6)
    # - local use 7  (local7)
    #           
    FACILITIES_CONSTANTS_MAPPING = {
      :kernel   => :LOG_KERN,
      :user     => :LOG_USER,
      :mail     => :LOG_MAIL,
      :daemon   => :LOG_DAEMON,
      :auth     => :LOG_AUTH,
      :syslog   => :LOG_SYSLOG,
      :lpr      => :LOG_LPR,
      :news     => :LOG_NEWS,
      :uucp     => :LOG_UUCP,
      :cron     => :LOG_CRON,
      :authpriv => :LOG_AUTHPRIV,
      :ftp      => :LOG_FTP,
      :local0   => :LOG_LOCAL0,
      :local1   => :LOG_LOCAL1,
      :local2   => :LOG_LOCAL2,
      :local3   => :LOG_LOCAL3,
      :local4   => :LOG_LOCAL4,
      :local5   => :LOG_LOCAL5,
      :local6   => :LOG_LOCAL6,
      :local7   => :LOG_LOCAL7
    }

    # Deletes undefined facilities, since their availability may vary from system to system
    # The authpriv facility may not exist on Solaris for instance
    SYSLOG_FACILITIES = Hash[
      FACILITIES_CONSTANTS_MAPPING
        .keep_if { |_, const_name| Syslog.const_defined?(const_name) }
        .map { |facility_alias, const_name| [facility_alias, Syslog.const_get(const_name)] }
    ]

    # Translation from Syslog severity levels to ruby's standard logger levels
    RUBY_STANDARD_LEVELS = Hash.new(5).merge({
      :debug    => 0, # Logger::DEBUG
      :info     => 1, # Logger::INFO
      :warning  => 2, # Logger::WARN
      :err      => 3, # Logger::ERROR
      :emerg    => 4, # Logger::FATAL
      :alert    => 4, # Logger::FATAL
      :crit     => 4  # Logger::FATAL
      # all other severities => Logger::UNKNOWN
    })

    attr_reader :app_name, :severity, :facility
    
    #
    # To build a Slogger::Base instance.
    #
    # +app_name+::                The appliaction name to be logged
    # +severity+::                The log severity.
    # +facility+::                A typical syslog facility
    # +custom_severity_levels+::  To be used by children classes. It defaults to
    #                               Slogger::Base::SYSLOG_SEVERITIES.
    #
    # Raises an ArgumentError if app_name, severity, or facility is nil.
    #
    def initialize(app_name, severity, facility, custom_severity_levels=SYSLOG_SEVERITIES)
      raise_argument_error_to_required_parameter "app_name" unless app_name
      raise_argument_error_to_required_parameter "severity" unless severity
      raise_argument_error_to_required_parameter "facility" unless facility

      raise_argument_error_to_invalid_parameter "severity", "SEVERITIES" unless custom_severity_levels[severity]
      raise_argument_error_to_invalid_parameter "facility", "FACILITIES" unless SYSLOG_FACILITIES[facility]

      @app_name = app_name
      @severity = severity
      @severity_as_int = custom_severity_levels[severity]
      @facility = facility
      @facility_as_int = SYSLOG_FACILITIES[facility]
      @custom_severity_levels = custom_severity_levels
      @mutex = Mutex.new
    end

    def level
      RUBY_STANDARD_LEVELS[severity]
    end

    def severity=(value)
      raise_argument_error_to_invalid_parameter "severity", "SEVERITIES" unless @custom_severity_levels[value]
      
      @severity = value
      @severity_as_int = @custom_severity_levels[severity]
    end

    def log(severity, message, &block)
      return if SYSLOG_SEVERITIES[severity] > @severity_as_int

      if block_given?
        benchmark = Benchmark.measure &block
        message = "[time: #{benchmark.real}] #{message}"
      end
      
      @mutex.synchronize do
        Syslog.open(@app_name, Syslog::LOG_PID, @facility_as_int) { |s| s.send severity, '%s', message }
      end
    end

    def raise_argument_error_to_required_parameter(param)
      raise ArgumentError, "The '#{param}' parameter is required."
    end

    def raise_argument_error_to_invalid_parameter(param, options)
      raise ArgumentError, "The '#{param}' parameter is invalid. Inspect the #{options} constant to know the options."
    end
  end
end
