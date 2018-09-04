require 'sf_message_base'

module Diameter
    SIGNIFICANT_AVPS = [268, 480, 416, 703]
    COMMANDS = { 271 => "AC", 272 => "CC", 306 => "UD", 307 => "PU", 308 => "SN", 309 => "PN" }
    APPLICATIONS = { 3 => "Rf", 4 => "Ro", 16777217 => "Sh" }

    class Message < MessageBase
        attr_reader :command, :application

        def self.create(message_data, direction, command_code, request_flag, application_id)
            application = APPLICATIONS[application_id]
            return if application.nil?
            if !$options[:hidden_messages]
                case application
                    when 'Rf' then return if !$options[:charging]
                    when 'Ro' then return if !$options[:charging]
                    when 'Sh' then return if !$options[:sh]
                end
            end
            command = COMMANDS[command_code]
            return if command.nil?
            if request_flag == 1
                command_name = command + 'R'
            else
                command_name = command + 'A'
            end
            return Message.new(message_data, command_name, application, direction)
        end

        def caption
            if @significant_avp != ''
                return "#{@command}[#{@significant_avp}]"
            else
                return "#{@command}"
            end
        end

        def text
            ''
        end
        
        def charging?
            return application == "Rf" || application == "Ro"
        end
        
        def sh?
            return application == "Sh"
        end

    private
        def initialize(message_data, command, application, direction)
            super(direction, :diameter, nil, nil)
            @command, @application = command, application
            @data = message_data
            init_significant_avp
        end

        def init_significant_avp
            avp_regex = /AVP: [\w\d-]*\((\d+)\).*val=(.*)/
            @significant_avp = ''
            most_significant_avp_found_index = SIGNIFICANT_AVPS.size
            @data.each_line do |line|
                if line =~ avp_regex
                    avp_code = $1.to_i
                    avp_value = $2
                    SIGNIFICANT_AVPS.each_with_index do |significant_avp_code, i|
                        if avp_code == significant_avp_code && i < most_significant_avp_found_index
                            @significant_avp = avp_value
                            most_significant_avp_found_index = i
                        end
                    end
                end
            end
        end
    end
end

