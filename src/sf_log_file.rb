require 'sf_sip'
require 'sf_megaco'
require 'sf_diameter'
require 'sf_service_event'

module LogFile
extend LogFile
    @@users = Set.new

    def users
        @@users
    end

    def read(fname)
        message_start_regexp_sipstack = /(Incoming|Outgoing) SIP message: (.*)/
        message_start_regexp_sipdispatcher_send = /Send SIP .*to.*\[\[\[(.*)/
        message_start_regexp_sipdispatcher_receive = /Message is:/
        session_side_regexp = /\((originating|terminating) side\) sending/
        timestamp_regexp = /(\d{2}:\d{2}:\d{2}\.\d+) /
        enter_sfw_dialog = /([A-Z,_]*\s*\d*) entered dialog with ID (\d*)/
        message_start_regexp_h248_send = /encodeH248Cmd(?:.*): (.*)/
        message_start_regexp_h248_receive = /decodeH248CmdReply(?:.*): (.*)/
        message_start_regexp_charging = /(A|C)C(R|A) (in|out)/
        service_event_capsule_abortion = /\| capsule abortion/i
        service_event_changed_state = /([^\s]+)\.cc:(?:.*)state change(?:.*): old state = (.+), new state = ([^\n.]+)/i
        service_event_changed_state2 = /([^\s]+)\.cc:(?:.*)state change (.+) -> ([^\n\s]+)/i
        
        search_for_sipdispatcher = true
        search_for_sipstack = true
        session_side = nil
        service_events = []
        messages = []
        timestamp = ''
        megaco_msg_type = ''
        diameter_command_code = nil
        diameter_application_id = nil
        diameter_request_flag = nil
        proc_reader = ProcessReader.new
        begin
            File.open(fname) do |in_file|
                while !in_file.eof? do
                    message = nil
                    protocol = :sip
                    line = in_file.readline
                    if line =~ timestamp_regexp
                        timestamp = $1
                    end
                    service_event = nil
                    if line =~ service_event_capsule_abortion # Always display Capsule abortion events as they are important enough?
                        event = extract_capsule_abortion_event(in_file, line)
                        msg = last_incoming_sip_message(messages)
                        unless msg.nil?
                            service_event = ServiceEvent.new("Capsule abortion", timestamp, event, msg, messages.last)
                        end
                    end
                    if $options[:service_events]
                        if line =~ service_event_changed_state || line =~ service_event_changed_state2
                            unless $2 == $3
                                msg = last_incoming_sip_message(messages)
                                unless msg.nil?
                                    service_event = ServiceEvent.new("State change " + $1, timestamp, $1 + "\n\nOld state: " + $2 + "\nNew state: " + $3, msg, messages.last)
                                end
                            end
                        end
                    end
                    unless service_event.nil?
                        service_events << service_event
                        next
                    end
                    if ($options[:diameter] || $options[:hidden_messages]) && line =~ message_start_regexp_charging
                        protocol = :diameter
                        if $1 == 'A'
                            diameter_command_code = 271
                        else
                            diameter_command_code = 272
                        end
                        if $2 == 'R'
                            diameter_request_flag = 1
                        else
                            diameter_request_flag = 0
                        end
                        if $3 == "in"
                            direction = :incoming
                        else
                            direction = :outgoing
                        end
                        message, diameter_application_id = extract_diameter_message_and_application_id(in_file)
                    end
                    if ($options[:megaco] || $options[:hidden_messages])
                        if line =~ message_start_regexp_h248_send
                            protocol = :megaco
                            megaco_msg_type = "Request"
                            direction = :outgoing
                            message = extract_megaco_message(in_file, $1 + "\n", false)
                        elsif line =~ message_start_regexp_h248_receive
                            protocol = :megaco
                            megaco_msg_type = "Response"
                            direction = :incoming
                            message = extract_megaco_message(in_file, $1 + "\n", true)
                        end
                    end
                    if search_for_sipdispatcher
                        if line =~ session_side_regexp
                            session_side = str_to_session_side($1)
                        elsif line =~ message_start_regexp_sipdispatcher_send
                            direction = :outgoing
                            message = extract_sip_message(in_file, $1 + "\n")
                            search_for_sipstack = false
                        elsif line =~ message_start_regexp_sipdispatcher_receive
                            in_file.readline
                            line = in_file.readline
                            direction = :incoming
                            message = extract_sip_message(in_file, line)
                            search_for_sipstack = false
                            session_side = extract_session_side_receive(in_file)
                        end
                    end
                    if search_for_sipstack
                        if line =~ message_start_regexp_sipstack
                            direction = $1 == 'Incoming' ? :incoming : :outgoing
                            message = extract_sip_message(in_file, $2 + "\n")
                            search_for_sipdispatcher = false
                        end
                    end
                    if !message.nil?
                        if protocol == :sip
                            sip_message = Sip::Message.create(message, direction, session_side, nil)
                            if $debug
                                puts "#{direction} #{message.lines.first}"
                            end
                            if sip_message_relevant?(sip_message)
                                sip_message.timestamp = timestamp
                                messages << sip_message
                                session_side = nil
                            end
                        elsif protocol == :megaco
                            megaco_message = Megaco::Message.new(message, direction, megaco_msg_type, '')
                            megaco_message.timestamp = timestamp
                            messages << megaco_message
                            megaco_message = nil
                        elsif protocol == :diameter
                            diameter_message = Diameter::Message.create(message, direction, diameter_command_code, diameter_request_flag, diameter_application_id)
                            next if diameter_message.nil?
                            diameter_message.timestamp = timestamp
                            messages << diameter_message
                            diameter_message = nil
                        end
                    end
                end
            end
        rescue Exception => e
            puts 'ERROR: ' + e.message
        end
        sort_messages(messages)
        if $options[:frame_interval]
            start_index = $options[:frame_interval_first].to_i - 1
            if start_index < 0
                start_index = 0
            end
            end_index = $options[:frame_interval_last].to_i - 1
            if end_index > messages.length - 1 
                end_index = messages.length - 1
            end
            messages = messages[start_index..end_index]
        end
        return messages, proc_reader.snapshots, service_events
    end

private
    def sort_messages(messages) # Stable sort
        n = 0
        messages.sort_by! {|x| n+= 1; [x.timestamp, n]}
    end

    def last_incoming_sip_message(messages)
        messages.reverse.each do |msg|
            if msg.sip? && msg.incoming?
                return msg
            end
        end
        return nil
    end

    def sip_message_relevant?(sip_message)
        return false if sip_message.nil?
        user = $options[:user]
        if !user.nil?
            unique_user = sip_message.user_wildcard_match?(user)
            if !unique_user.nil?
                @@users.add?(unique_user)
            else
                return false
            end
        end
        filter = $options[:filter]
        return true if filter.nil?
        headers = sip_message.headers
        if sip_message.request?
            status_code = 1000
        else
            status_code = sip_message.status_code.to_i
        end
        eval(filter)
    end

    def extract_sip_message(file, line)
        content_length_header_regexp = /Content-Length:\s*(\d*)/
        message = filter_line(line)
        content_length = 0
        while line != "\r\n" && !file.eof?
            line = filter_line(file.readline)
            if line[0] == '#' || line.index("E_HIS")
                break
            end
            message << line
            if line =~ content_length_header_regexp
                content_length = $1.to_i
            end
        end
        if content_length > 0
            num_read = 0
            while num_read < content_length && !file.eof?
                line = filter_line(file.readline)
                if line[0] == '#' || line.index("E_HIS")
                    break
                end
                message << line
                num_read += line.size
            end
        end
        return message
    end

    def extract_megaco_message(file, line, recieve)
        message = filter_line(line)
        bracket_count = message.count('{') - message.count('}')
        if recieve
            bracket_count += 1
        end
        while !file.eof?
            if bracket_count <= 0
                break
            end
            line = filter_line(file.readline)
            if line[0] == '#' || line.index("E_HIS")
                break
            end
            message << line
            bracket_count += line.count('{') - line.count('}')
        end
        return message
    end

    def extract_diameter_message_and_application_id(file)
        message = ""
        application_id = nil
        while !file.eof?
            line = filter_line(file.readline)
            if line == "\r\n" || line.index("E_HIS")
                break
            end
            if line =~ /Application-Id: (\d+)/
                application_id = $1.to_i
            end
            message << line
        end
        return message, application_id
    end

    def extract_capsule_abortion_event(file, line)
        event = filter_line(line)
        while line != "\r\n" && !file.eof?
            line = filter_line(file.readline)
            event << line
        end
        return event
    end

    def filter_line(line)
        if line.index('APP-TRACE') || line.index(/\d{2}:\d{2}:\d{2}.\d{3}\sDEBUG/)
            return ''
        end
        line.gsub!(/(CEST|CET|JST).{25}/, '')
        line.lstrip!
        line.chop!
        line << "\r\n"  # Replace any '\n' from processed logs with '\r\n'.
    end

    def extract_session_side_receive(file)
        session_side_regexp = /\((originating|terminating) side\) in APP/
        num_lines_searched = 0
        while num_lines_searched < 100 && !file.eof?
            line = file.readline
            if line =~ session_side_regexp
                return str_to_session_side($1)
            end
            num_lines_searched += 1
        end
    end

    def str_to_session_side(str)
        return :orig if str == 'originating'
        return :term if str == 'terminating'
    end

    class ProcessReader
        CAPSULE_START = /Capsule: (\d+) starts here!/             # Only present in loganalyzer files.
        APPLICATION_PROC_CAPSULE = /(\d+) ApplicationProcess \d*/ # Only present in Processor logs.

        attr_reader :snapshots

        def initialize
            @current_capsule = nil
            @capsules = Hash.new
            @snapshots = []
        end

        def read_line(line)
            if line =~ CAPSULE_START || line =~ APPLICATION_PROC_CAPSULE
                capsule_id = $1.to_i
                if capsule_id != @current_capsule.id
                    set_current_capsule(capsule_id)
                    puts "\n----------- Capsule #{capsule_id} start -----------\n\n"
                end
            end
            @current_capsule.read_line(line) unless @current_capsule.nil?
        end

        def observe_message(message)
            @current_capsule.observe_message(message) unless @current_capsule.nil?
        end

        def eof
            @current_capsule.eof
        end

    private
        def set_current_capsule(capsule_id)
            @current_capsule = @capsules[capsule_id]
            if @current_capsule.nil?
                @current_capsule = Capsule.new(capsule_id, @snapshots)
                @capsules[capsule_id] = @current_capsule
            end
        end
    end

    class Capsule
        SERVICE_SESSION_CREATE = /create serviceSession/
        SERVICE_SESSION_ENTER = /([A-Z,_]*\s*\d*) received from dialog (\d+)::(\d+)/
        SERVICE_SESSION_ENTER_2 = /([A-Z,_]*\s*\d*) for dialog (\d+)::(\d+)/
        SFW_DIALOG_CREATE = /(Incoming call|Outgoing call|Register)-dialog created with sourceID (\d+)/
        SFW_DIALOG_ENTER = /([A-Z,_]*\s*\d*) entered dialog with ID (\d+)/
        SFW_DIALOG_ADD = /Dialog (\d+)::(\d+) is added/
        SFW_DIALOG_REMOVE = /Dialog (\d+)::(\d+) terminated/

        attr_reader :id

        def initialize(id, snapshots)
            @id, @snapshots = id, snapshots
            @current_snapshot = Snapshot.new
            @created_dialog = nil
            @sessions = Hash.new
            @removed_dialogs = []
        end

        def read_line(line)
            if line =~ SERVICE_SESSION_CREATE
                puts "    Create service session\n"
            end
            if line =~ SFW_DIALOG_CREATE && !line.include?('SIP')
                type = $1
                id = $2.to_i
                create_sfw_dialog(type, id)
                puts "    #{type} dialog created with id #{id}\n"
            end
            if line =~ SFW_DIALOG_ADD
                dialog_id = $2.to_i
                session_id = $1.to_i
                add_sfw_dialog_to_session(dialog_id, session_id)
                puts "    Dialog #{$2} added to service session #{$1}\n"
            end
            if line =~ SFW_DIALOG_REMOVE
                dialog_id = $2.to_i
                session_id = $1.to_i
                @removed_dialogs << { :dialog_id => dialog_id, :session_id => session_id }
                puts "    Dialog #{$2} removed from service session #{$1}\n"
            end
            if line =~ SFW_DIALOG_ENTER
                sfw_event = $1
                dialog_id = $2.to_i
                source = 'SIP' if line.include?('from SIP')
                if @current_snapshot.already_entered_dialog?(dialog_id)
                    # We should not enter the same dialog twice within one snapshot. Hard to
                    # display that.
                    next_snapshot
                end
                @current_snapshot.enter_dialog(dialog_id, sfw_event)
                puts "    Event \"#{sfw_event}\" entered dialog #{dialog_id} from #{source}\n"
            end
            if line =~ SERVICE_SESSION_ENTER || line =~ SERVICE_SESSION_ENTER_2
                sfw_event = $1
                session_id = $2.to_i
                from_dialog_id = $3.to_i
                @current_snapshot.enter_service_session(session_id, from_dialog_id, sfw_event)
                puts "    Event \"#{sfw_event}\" entered session #{session_id} from dialog #{from_dialog_id}\n"
            end
        end

        def observe_message(message)
            if message.outgoing?
                message.snapshot_id = @current_snapshot.id
                if @current_snapshot.traversed_any_dialogs?
                    next_snapshot
                end
            else
                if @current_snapshot.traversed_any_dialogs?
                    next_snapshot
                end
                message.snapshot_id = @current_snapshot.id
            end
        end

        def eof
            next_snapshot
        end

    private
        def create_sfw_dialog(dialog_type, id)
            type = nil
            case dialog_type
            when 'Incoming call'
                type = :incoming
            when 'Outgoing call'
                type = :outgoing
            when 'Register'
                type = :register
            else
                type = :unknown
            end
            @created_dialog = SfwDialog.new(type, id)
        end

        def add_sfw_dialog_to_session(dialog_id, session_id)
            session = @sessions[session_id]
            if session.nil?
                session = SfwSession.new(session_id)
                @sessions[session_id] = session
            end
            if @created_dialog.nil? || @created_dialog.id != dialog_id
                session.add_dialog(SfwDialog.new(:unknown, dialog_id))
                puts "INFO: Dialog #{dialog_id} of unknown type added to session #{session_id}"
            else
                session.add_dialog(@created_dialog)
            end
        end

        def remove_sfw_dialog(dialog_id, session_id)
            session = @sessions[session_id]
            unless session.nil?
                session.remove_dialog(dialog_id)
            end
        end

        def next_snapshot
            puts "===== next snapshot ====="
            @current_snapshot.sessions = @sessions
            @current_snapshot.capsule_id = @id
            @current_snapshot.encode
            @snapshots << @current_snapshot
            @current_snapshot = Snapshot.new
            @removed_dialogs.each do |dialog_keys|
                remove_sfw_dialog(dialog_keys[:dialog_id], dialog_keys[:session_id])
            end
            @removed_dialogs.clear
        end
    end

    class SfwDialog
        attr_reader :id

        def initialize(type, id)
            @type = type
            @id = id
        end

        def encode
            s = ' { '
            s << "id: \"#{@id}\", "
            s << "type: \"#{@type.to_s}\" "
            s << '}'
        end
    end

    class SfwSession
        attr_reader :id

        def initialize(id)
            @id = id
            @dialogs = Hash.new
        end

        def add_dialog(dialog)
            @dialogs[dialog.id] = dialog
        end

        def remove_dialog(dialog_id)
            @dialogs.delete(dialog_id)
        end

        def encode
            s = '{ '
            s << "id: \"#{@id}\", "
            s << 'dialogs: ['
            num_encoded_dialogs = 0
            @dialogs.each do |id, dialog|
                s << dialog.encode
                num_encoded_dialogs += 1
                s << ',' if num_encoded_dialogs < @dialogs.size
            end
            s << ' ] }'
        end
    end

    class Snapshot
        attr_accessor :sessions, :capsule_id
        attr_reader :id, :javascript_code

        @@last_available_id = 0

        def initialize
            @id = @@last_available_id
            @@last_available_id += 1
            @events = []
            @traversed_dialogs = Set.new
        end

        def enter_dialog(dialog_id, sfw_event)
            @events << EnterDialogEvent.new(dialog_id, sfw_event)
            @traversed_dialogs.add(dialog_id)
        end

        def already_entered_dialog?(dialog_id)
            @traversed_dialogs.include?(dialog_id)
        end

        def traversed_any_dialogs?
            @traversed_dialogs.size > 0
        end

        def enter_service_session(session_id, from_dialog_id, sfw_event)
            @events << EnterServiceSessionEvent.new(session_id, from_dialog_id, sfw_event)
        end

        def encode
            s = "    var capsule_id = #{capsule_id};\n    var sessions = [ "
            num_encoded_sessions = 0
            @sessions.each do |id, session|
                s << session.encode
                num_encoded_sessions += 1
                s << ', ' if num_encoded_sessions < @sessions.size
            end
            s << " ];\n    var events = [ "
            num_encoded_events = 0
            @events.each do |event|
                s << event.encode
                num_encoded_events += 1
                s << ', ' if num_encoded_events < @events.size
            end
            s << " ];\n"
            @javascript_code = s
        end
    end

    class EnterDialogEvent
        def initialize(dialog_id, sfw_event)
            @dialog_id, @sfw_event = dialog_id, sfw_event
        end

        def encode
            s = "{ type: \"enter_dialog\", "
            s << "dialog_id: \"#{@dialog_id}\", "
            s << "sfw_event: \"#{@sfw_event}\" "
            s << '}'
        end
    end

    class EnterServiceSessionEvent
        def initialize(session_id, from_dialog_id, sfw_event)
            @session_id, @from_dialog_id, @sfw_event = session_id, from_dialog_id, sfw_event
        end

        def encode
            s = "{ type: \"enter_service_session\", "
            s << "session_id: \"#{@session_id}\", "
            s << "from_dialog_id: \"#{@from_dialog_id}\", "
            s << "sfw_event: \"#{@sfw_event}\" "
            s << '}'
        end
    end
end



