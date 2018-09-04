require 'sf_message_base'
require 'sf_pcap_file'

module Sip
    CALL_ID = "Call-ID"
    TO = "To"
    FROM = "From"
    CSEC = "CSeq"
    SERVER = "Server"
    USER_AGENT = "User-Agent"
    P_SERVED_USER = "P-Served-User"
    P_PROFILE_KEY = "P-Profile-Key"
    CONTACT = "Contact"
    VIA = "Via"

    class Message < MessageBase
        attr_reader :body, :headers, :to_tag, :from_tag
        attr_accessor :duplicate, :early_dialog_id

        def call_id
            @headers[CALL_ID]
        end

        def to
            @headers[TO]
        end

        def to_user_info
            Message.user_info_part_from_uri(to)
        end

        def from
            @headers[FROM]
        end

        def from_user_info
            Message.user_info_part_from_uri(from)
        end

        def c_seq
            @headers[CSEC]
        end

        def server
            @headers[SERVER]
        end

        def user_agent
            @headers[USER_AGENT]
        end

        def request?
            self.class == Request
        end

        def response?
            self.class == Response
        end

        def set_inverted_direction(direction)
            if direction == :incoming
                @direction = :outgoing
            else
                @direction = :incoming
            end
        end

        def self.create(message_buffer, direction, session_side, as_type)
            message = nil
            first_line = message_buffer.lines.next
            if first_line =~ /SIP\/2\.0\s*(\d{3})\s*(.*)/
                status_code = $1
                reason_phrase = $2
                headers = parse_headers(message_buffer)
                if direction == :outgoing
                    if session_side.nil?
                        session_side = get_session_side_from_contact_header(headers)
                    end
                    if as_type.nil?
                        as_type = get_as_type_from_contact_header(headers)
                    end
                else
                    if session_side.nil?
                        session_side = get_session_side_from_via_header(headers)
                    end
                    if as_type.nil?
                        as_type = get_as_type_from_via_header(headers)
                    end
                end
                to_tag = get_tag_from_to_header(headers)
                from_tag = get_tag_from_from_header(headers)
                message = Response.new(status_code, reason_phrase, headers, '', direction, session_side, as_type, to_tag, from_tag)
            elsif first_line =~ /([A-Z]*)\s*(.*)\s*SIP\/2\.0/
                method = $1
                uri = $2
                headers = parse_headers(message_buffer)
                if direction == :incoming
                    if session_side.nil?
                        session_side = get_session_side_from_method(first_line)
                    end
                    if as_type.nil?
                        as_type = get_as_type_from_method(first_line)
                    end
                    if headers.include?(P_PROFILE_KEY) # Orig SDS AS can get an invite with p-profile-key (sds_camel_telenor.pcap) but the mtas name gets overwritten by information from the camel messages so no problem?
                        if session_side.nil?
                            session_side = :term
                        end
                        if as_type.nil?
                            as_type = :st
                        end
                    end
                else
                    if session_side.nil?
                        session_side = get_session_side_from_contact_header(headers)
                        if session_side.nil?
                            session_side = get_session_side_from_via_header(headers)
                        end
                    end
                    if as_type.nil?
                        as_type = get_as_type_from_contact_header(headers)
                        if as_type.nil?
                            as_type = get_as_type_from_via_header(headers)
                        end
                    end
                end
                psu_session_side = get_session_side_from_psu_header(headers)
                unless psu_session_side.nil?
                    session_side = psu_session_side
                end
                to_tag = get_tag_from_to_header(headers)
                from_tag = get_tag_from_from_header(headers)
                message = Request.new(method, uri, headers, '', direction, session_side, as_type, to_tag, from_tag)
            end
            message.data = message_buffer if !message.nil?
            return message
        end

        def self.user_info_part_from_uri(uri_in)
            return if uri_in.nil?
            uri = uri_in.gsub(/".*"/, '')
            if uri =~ /tel:/
                uri.match(/tel:\s*([0-9\-\+\(\)\s]*)/)
            else
                uri.match(/sip:([^;>]*)/)
                if $1.nil?
                    uri.match(/sip:([0-9,\.,:,a-f,A-F]*)/)
                end
            end
            if $1.nil?
                return uri_in
            end
            $1.strip
        end

        def user_is?(user)
            to_user_info == user || from_user_info == user
        end

        def user_wildcard_match?(user)
            to_user = to_user_info
            from_user = from_user_info
            if to_user.include?(user)
                return to_user
            elsif from_user.include?(user)
                return from_user
            else
                return nil
            end
        end

    protected
        def initialize(headers, body, direction, session_side, as_type, to_tag, from_tag)
            super(direction, :sip, session_side, as_type)
            @headers, @body, @direction, @to_tag, @from_tag = headers, body, direction, to_tag, from_tag
            @duplicate = false
        end

        def equals(other)
            call_id == other.call_id && c_seq == other.c_seq
        end

        def text
            info = String.new
            if !c_seq.nil?
                info += CSEC + ': ' + c_seq
            end
            return info
        end

    private
        def self.parse_headers(message_buffer)
            headers = Hash.new
            header_regexp = /([\w-]*)\s*:\s*(.*)/
            message_buffer.lines.each_with_index do |line, i|
                next if i == 0
                break if line.chop.empty?
                if line =~ header_regexp
                    headers[$1] = $2.chop
                else
                    puts 'WARNING: Failed to parse header in SIP message: ' + line
                end
            end
            return headers
        end
        
        def self.get_session_side_from_via_header(headers)
            side = nil
            if !headers[VIA].nil? && headers[VIA] =~ /SIP\/.+?:(\d+);/
                side = PcapFile.session_side_from_port($1.to_i)
            end
            return side
        end
        
        def self.get_as_type_from_via_header(headers)
            type = nil
            if !headers[VIA].nil? && headers[VIA] =~ /SIP\/.+?:(\d+);/
                type = PcapFile.as_type_from_port($1.to_i)
            end
            return type
        end
        
        def self.get_session_side_from_contact_header(headers)
            side = nil
            if !headers[CONTACT].nil? && headers[CONTACT] =~ /sip:.+?:(\d+)(?:;|\s|$)/
                side = PcapFile.session_side_from_port($1.to_i)
            end
            return side
        end
        
        def self.get_as_type_from_contact_header(headers)
            type = nil
            if !headers[CONTACT].nil? && headers[CONTACT] =~ /sip:.+?:(\d+)(?:;|\s|$)/
                type = PcapFile.as_type_from_port($1.to_i)
            end
            return type
        end
        
        def self.get_session_side_from_method(method)
            side = nil
            if method =~ /sip:.+:(\d+)(?:\s|;)/
                side = PcapFile.session_side_from_port($1.to_i)
            end
            return side
        end
        
        def self.get_as_type_from_method(method)
            type = nil
            if method =~ /sip:.+:(\d+)(?:\s|;)/
                type = PcapFile.as_type_from_port($1.to_i)
            end
            return type
        end
        
        def self.get_session_side_from_psu_header(headers)
            psu_header = headers[P_SERVED_USER]
            unless psu_header.nil?
                if psu_header.include?('sescase=orig')
                    return :orig
                elsif psu_header.include?('sescase=term')
                    return :term
                end
            end
            return nil
        end
        
        def self.get_tag_from_to_header(headers)
            to_header = headers[TO]
            unless to_header.nil?
                if to_header =~ /;tag=(.+)/
                    return $1
                end
            end
            return nil
        end
        
        def self.get_tag_from_from_header(headers)
            from_header = headers[FROM]
            unless from_header.nil?
                if from_header =~ /;tag=(.+)/
                    return $1
                end
            end
            return nil
        end
    end

    class Request < Message
        attr_reader :method, :uri

        def initialize(method, uri, headers, body, direction, session_side, as_type, to_tag, from_tag)
            super(headers, body, direction, session_side, as_type, to_tag, from_tag)
            @method, @uri = method, uri
        end

        def equals(other)
            return false if other.class != Request
            @method == other.method && super(other)
        end

        def uri_user_info
            Message.user_info_part_from_uri(@uri)
        end

        def text
            user = uri_user_info
            if user.nil? || user.empty?
                user = @uri
            end
            user + "\r\n" + super
        end

        def caption
            @method
        end

        def caption=(value)
            @method = value
        end

        def request?
            true
        end
        
    end

    class Response < Message
        attr_reader :status_code, :reason_phrase

        def initialize(status_code, reason_phrase, headers, body, direction, session_side, as_type, to_tag, from_tag)
            super(headers, body, direction, session_side, as_type, to_tag, from_tag)
            @status_code, @reason_phrase = status_code, reason_phrase
        end

        def equals(other)
            return false if other.class != Response
            @status_code == other.status_code && super(other)
        end

        def text
            @reason_phrase + "\r\n" + super
        end

        def caption
            @status_code
        end

        def caption=(value)
            @status_code = value
        end
        
        def response?
            true
        end
    end

    AS = 'AS'

    class Endpoint
        attr_accessor :name
        
        def set_mtas_name(session_side, as_type, served_user)
            session_side_str = ""
            as_type_str = ""
            served_user_str = ""
            unless session_side.nil?
                session_side_str = session_side.to_s.capitalize + ' '
            end
            unless as_type.nil?
                as_type_str = as_type.to_s.upcase + ' '
            end
            unless served_user.nil?
                served_user_str = ' ' + served_user
            end
            @name = session_side_str + as_type_str + AS + served_user_str
        end
    end

    class Dialog
        attr_reader :end_to_end_id, :incomplete, :to, :from, :icid_value, :from_sdp_connection, :to_sdp_connection, :to_from_tag_ids
        attr_accessor :remote_endpoint, :mtas_endpoint

        def initialize
            @messages = []
            @incomplete = false
            @mts_to_mtas = false
            @mtas_endpoint = Endpoint.new
            @remote_endpoint = Endpoint.new
            @icid_value = nil
            @from_sdp_connection = nil
            @to_sdp_connection = nil
            @to_from_tag_ids = Hash.new
            @initial_invite = nil
            @is_early = false
        end

        def add_message(message)
            if @messages.empty?
                @from = message.from_user_info
                @to = message.to_user_info
                #@uri = message.uri_user_info
            end
            clone = find_duplicate_message(message)
            unless clone.nil?
                if !@mts_to_mtas && @is_early
                    @mts_to_mtas = true
                end
                if @mts_to_mtas
                    set_duplicate_message(message, clone)
                end
            end
            if @is_early && !(message.to_tag.nil? || message.from_tag.nil?)
                if (message.to_tag <=> message.from_tag) == -1 # check if to_tag "less than" from_tag
                    key = message.to_tag + message.from_tag
                else
                    key = message.from_tag + message.to_tag
                end
                unless @to_from_tag_ids.has_key?(key)
                    @to_from_tag_ids[key] = 1 + @to_from_tag_ids.length
                end
                message.early_dialog_id = @to_from_tag_ids[key]
            end
            if message.request? && !message.method.nil? && message.method == "INVITE" && !message.to.nil? && !message.to.downcase.include?(";tag=") && !message.c_seq.nil?
                @initial_invite = message
                @is_early = true
            end
            if @is_early && message.response? && !message.status_code.nil? && message.status_code == "200" && !message.c_seq.nil? && message.c_seq == @initial_invite.c_seq
                @is_early = false
            end
            @messages << message
        end

        def update_end_to_end_id
            @end_to_end_id = @icid_value.nil? ? "" : @icid_value#initial_request.from_user_info + initial_request.to_user_info
            @messages.each do |message|
                message.end_to_end_id = @end_to_end_id
            end
        end

        def calculate_icid_and_sdp_connection
            @messages.each do |message|
                if @icid_value.nil? && !message.headers["P-Charging-Vector"].nil? && message.headers["P-Charging-Vector"] =~ /icid-value=(.+?)(?:;|$)/
                    @icid_value = $1
                end
                if !message.headers["Content-Type"].nil? && message.headers["Content-Type"].downcase.include?("application/sdp")
                    ip = nil
                    port = nil
                    message.data.each_line.to_a.reverse.each do |line|
                        if ip.nil? && line.start_with?("c=") && line =~ /c=([^\r\n]+)/
                            ip = $1
                        elsif port.nil? && line.start_with?("m=") && line =~ /m=.+?\s(\d+)\s/
                            port = $1
                        end
                        unless ip.nil? || port.nil?
                            if same_direction?(message)
                                @from_sdp_connection = ip + port
                            else
                                @to_sdp_connection = ip + port
                            end
                        end
                    end
                end
            end
        end

        def calculate_endpoints()
            if @mts_to_mtas
                calculate_remote_mtas_endpoint()
            else
                calculate_remote_endpoint
            end
            calculate_mtas_endpoint
        end

        def find_request_from_response(response)
            @messages.each do |m|
                if response.c_seq == m.c_seq && m.request?
                    return m
                end
            end
            return nil
        end

        def mtas_to_mtas?
            @mts_to_mtas
        end

        def initial_request
            if @messages.first.request? && !@messages.first.to.nil? && !@messages.first.to.downcase.include?(";tag=")
                return @messages.first
            end
            return nil
        end
        
        def same_direction?(msg)
            if msg.to_user_info == to && msg.from_user_info == from
                if msg.request?
                    if @messages.first.request?
                        return true
                    end
                elsif @messages.first.response?
                    return true
                end
            elsif msg.response?
                if @messages.first.request?
                    return true
                end
            elsif @messages.first.response?
                return true
            end
            return false
        end

        # def strictly_related?(other)
            # other.to == to && other.from == from && other.uri == uri
        # end

        # def related?(other)
            # other.to == to || other.from == from || other.uri == uri
        # end

        # def loosely_related?(other)
            # other.to == to || other.from == from || other.uri == uri || other.to == from || other.from == to
        # end

        # def incoming?
            # direction == :incoming
        # end

        # def outgoing?
            # direction == :outgoing
        # end

        def to_s
            s = "dialog:\n  remote: #{@remote_endpoint.name}\n  mtas: #{@mtas_endpoint.name}\n  call-id: #{@messages[0].call_id}\n  mtas_to_mtas: #{mtas_to_mtas?}\n  from: #{@from}\n  to: #{@to}\n"
            @messages.each do |sip_message|
                s << "    #{sip_message.caption} #{sip_message.direction} #{sip_message.as_type} #{sip_message.session_side} #{sip_message.duplicate}\n"
            end
            return s
        end

    private
        # Messages sent on dialogs from MTAS to MTAS appear twice; once from MTAS to CSCF
        # and once from CSCF to MTAS. One of those two messages are considered a duplicate
        # and will not be displayed. Choose the duplicate according to the following:
        #
        #   remote MTAS          CSCF           MTAS
        #        |                |              |
        #        | duplicate=true |              |
        #        |-----INVITE---->|----INVITE--->|
        #        |                |              |
        #        | duplicate=true |              |
        #        |<-----100-------|<----100------|
        #        |                |              |
        #
        def set_duplicate_message(message, clone)
            if message.request?
                if message.from_user_info == @from && message.to_user_info == @to
                    if clone.outgoing? && message.incoming?
                        clone.duplicate = true
                    else
                        message.duplicate = true
                    end
                else
                    if clone.outgoing? && message.incoming?
                        message.duplicate = true
                    else
                        clone.duplicate = true
                    end
                end
            else
                if message.from_user_info == @from && message.to_user_info == @to
                    if clone.outgoing? && message.incoming?
                        message.duplicate = true
                    else
                        clone.duplicate = true
                    end
                else
                    if clone.outgoing? && message.incoming?
                        clone.duplicate = true
                    else
                        message.duplicate = true
                    end
                end
            end
        end

        def calculate_remote_endpoint
            msg = @messages.first
            if msg.direction == :incoming
                if msg.request?
                    if msg.method == 'REGISTER'
                        @remote_endpoint.name = msg.to_user_info
                    else
                        @remote_endpoint.name = msg.from_user_info
                    end
                else
                    @remote_endpoint.name = msg.to_user_info
                end
            elsif msg.request?
                @remote_endpoint.name = msg.uri_user_info
            elsif !msg.c_seq.nil? && msg.c_seq.downcase.include?("register")
                @remote_endpoint.name = msg.to_user_info
            else
                @remote_endpoint.name = msg.from_user_info
            end
        end

        def calculate_remote_mtas_endpoint()
            session_side = nil
            as_type = nil
            served_user = nil
            @messages.each do |msg|
                if same_direction?(msg) # Message heading away from remote MTAS
                    if msg.outgoing?
                        if session_side.nil?
                            session_side = msg.session_side
                        end
                        if as_type.nil?
                            as_type = msg.as_type
                        end
                    end
                else # Message heading towards remote MTAS
                    if msg.incoming?
                        if session_side.nil?
                            session_side = msg.session_side
                        end
                        if as_type.nil?
                            as_type = msg.as_type
                        end
                    end
                end
                break unless (session_side.nil? || as_type.nil?)
            end
            if $options[:split_mtas]
                @messages.each do |msg|
                    if !msg.headers[P_SERVED_USER].nil? && ((msg.incoming? && !same_direction?(msg)) || (msg.outgoing? && same_direction?(msg)))
                        if msg.headers[P_SERVED_USER] =~ /:([^;>]*)/
                            served_user = $1
                            break
                        end
                    end
                end
            end
            @remote_endpoint.set_mtas_name(session_side, as_type, served_user)
        end

        def calculate_mtas_endpoint
            session_side = nil
            as_type = nil
            served_user = nil
            @messages.each do |msg|
                if !mtas_to_mtas? # Not MTAS to MTAS, we can search all messages for session side/as type information
                    if session_side.nil?
                        session_side = msg.session_side
                    end
                    if as_type.nil?
                        as_type = msg.as_type
                    end
                else
                    if same_direction?(msg) # Message heading towards MTAS
                        if msg.incoming?
                            if session_side.nil?
                                session_side = msg.session_side
                            end
                            if as_type.nil?
                                as_type = msg.as_type
                            end
                        end
                    else # Message heading away from MTAS
                        if msg.outgoing?
                            if session_side.nil?
                                session_side = msg.session_side
                            end
                            if as_type.nil?
                                as_type = msg.as_type
                            end
                        end
                    end
                end
                break if !session_side.nil? && !as_type.nil?
            end
            if $options[:split_mtas]
                @messages.each do |msg|
                    if !msg.headers[P_SERVED_USER].nil?
                        if !mtas_to_mtas? || (msg.incoming? && same_direction?(msg)) || (msg.outgoing? && !same_direction?(msg))
                            if msg.headers[P_SERVED_USER] =~ /:([^;>]*)/
                                served_user = $1
                                break
                            end
                        end
                    end
                end
            end
            @mtas_endpoint.set_mtas_name(session_side, as_type, served_user)
        end

        def find_duplicate_message(message)
            @messages.last(3).each do |m|
                if message.equals(m) && m.direction != message.direction
                    return m
                end
            end
            return nil
        end
    end
end

