require 'sf_message_base'
require 'sf_sip'

module Tcap
    @@mtas_pcs = Set.new # Todo, if we can't determine dialog endpoints, maybe go by pointcodes from other dialogs?
    @@scf_pcs = Set.new # Todo
    @@mcs_pcs = Set.new # Todo
    
    class Message < MessageBase
        attr_reader :o_tid, :d_tid
        def self.create(message_data, primitive)
            o_tid = nil
            d_tid = nil
            message_data.lines.each do |line|
                if o_tid.nil? && line =~ /otid: (.+)/
                    o_tid = $1
                elsif d_tid.nil? && line =~ /dtid: (.+)/
                    d_tid = $1
                end
            end
            return Message.new(message_data, o_tid, d_tid, primitive)
        end
        
        def text
            return ''
        end
        
        def caption
            return "TCAP #{@primitive}"
        end
    private
        def initialize(message_data, o_tid, d_tid, primitive)
            super(nil, :tcap, nil, nil)
            @o_tid = o_tid
            @d_tid = d_tid
            @primitive = primitive
            @data = message_data
        end
    end

    class Dialog
        attr_reader :o_tid, :d_tid, :first_initial_DP, :first_connect
        
        def initialize(first_msg)
            @messages = []
            @originating_endpoint = Sip::Endpoint.new
            @destination_endpoint = Sip::Endpoint.new
            @o_tid = first_msg.o_tid
            @d_tid = first_msg.d_tid
            @first_initial_DP = nil
            @first_connect = nil
            @end_to_end_id = ""
            add_message?(first_msg)
        end
        
        def same_direction?(msg)
            if ((!msg.o_tid.nil? && msg.o_tid == @o_tid) || (!msg.d_tid.nil? && msg.d_tid == @d_tid))
                return true
            end
            return false
        end

        def add_message?(msg)
            if ((!msg.o_tid.nil? && (msg.o_tid == @o_tid || msg.o_tid == @d_tid)) || (!msg.d_tid.nil? && (msg.d_tid == @o_tid || msg.d_tid == @d_tid)))
                if !msg.o_tid.nil?
                    if same_direction?(msg)
                        if @o_tid.nil?
                            @o_tid = msg.o_tid
                        end
                    elsif @d_tid.nil?
                        @d_tid = msg.o_tid
                    end
                end
                if !msg.d_tid.nil?
                    if same_direction?(msg)
                        if @d_tid.nil?
                            @d_tid = msg.d_tid
                        end
                    elsif @o_tid.nil?
                        @o_tid = msg.d_tid
                    end
                end
                if @first_initial_DP.nil? && msg.data.include?("local: initialDP")
                    @first_initial_DP = msg
                elsif @first_connect.nil? && msg.data.include?("local: connect")
                    @first_connect = msg
                end
                @messages << msg
                return true
            else
                return false
            end
        end
        
        def calculate_endpoints(messages, dialogs)
            return if @first_initial_DP.nil?
            idp_called_party_number = nil
            idp_event_type = nil
            @first_initial_DP.data.lines.each do |line|
                if idp_called_party_number.nil? && line =~ /BCD Digits: [A|B|C|D|E|F]*(\d+)[A|B|C|D|E|F]*/
                    idp_called_party_number = $1.sub(/^0+/, "") # Remove leading zeroes
                elsif idp_called_party_number.nil? && line =~ /Called Party Number: [A|B|C|D|E|F]*(\d+)[A|B|C|D|E|F]*/
                    idp_called_party_number = $1.sub(/^0+/, "") # Remove leading zeroes
                elsif idp_event_type.nil? && line =~ /eventTypeBCSM: (.+)/
                    idp_event_type = $1
                end
            end
            scf_case = false
            if !idp_called_party_number.nil?
                messages.reverse.each do |msg|
                    next unless (msg.incoming? && msg.frame_number < @first_initial_DP.frame_number && msg.sip? && msg.request? && msg.method == "INVITE" && !dialogs[msg.call_id].nil?)
                    mtas_endpoint = nil
                    if !dialogs[msg.call_id].mtas_to_mtas? || dialogs[msg.call_id].same_direction?(msg)
                        mtas_endpoint = dialogs[msg.call_id].mtas_endpoint
                    else
                        mtas_endpoint = dialogs[msg.call_id].remote_endpoint
                    end
                    if msg.uri.include?(idp_called_party_number)
                        if same_direction?(@first_initial_DP)
                            @originating_endpoint = mtas_endpoint
                            @destination_endpoint.name = "SCF"
                        else
                            @originating_endpoint.name = "SCF"
                            @destination_endpoint = mtas_endpoint
                        end
                        @end_to_end_id = msg.end_to_end_id
                        scf_case = true
                        break
                    end
                end
            end
            if !scf_case && !@first_connect.nil?
                connect_called_party_number = nil
                
                found_connect = false
                @first_connect.data.lines.each do |line|
                    if line.downcase.include?("connectarg")
                        found_connect = true
                        next
                    end
                    if found_connect && connect_called_party_number.nil? && line =~ /Called Party Number: [A|B|C|D|E|F]*(\d+)[A|B|C|D|E|F]*/
                        connect_called_party_number = $1.sub(/^0+/, "") # Remove leading zeroes
                        break
                    end
                end
                if !connect_called_party_number.nil?
                    messages.each do |msg|
                        next unless (msg.incoming? && msg.frame_number > @first_connect.frame_number && msg.sip? && msg.request? && msg.method == "INVITE" && !dialogs[msg.call_id].nil?)
                        mtas_endpoint = nil
                        if !dialogs[msg.call_id].mtas_to_mtas? || dialogs[msg.call_id].same_direction?(msg)
                            mtas_endpoint = dialogs[msg.call_id].mtas_endpoint
                        else
                            mtas_endpoint = dialogs[msg.call_id].remote_endpoint
                        end
                        if msg.uri.include?(connect_called_party_number) && !idp_event_type.nil? && (!idp_event_type.include?("termAttemptAuthorized") || mtas_endpoint.name.downcase.include?("scc"))
                            if (idp_event_type.include?("collectedInfo"))
                                mtas_endpoint.set_mtas_name("Orig", "SDS", nil)
                            end
                            if same_direction?(@first_connect)
                                @originating_endpoint = mtas_endpoint
                                @destination_endpoint.name = "MSC"
                            else
                                @originating_endpoint.name = "MSC"
                                @destination_endpoint = mtas_endpoint
                            end
                            @end_to_end_id = msg.end_to_end_id
                            break
                        end
                    end
                end
            end
        end
        
        def set_message_endpoints
            @messages.each do |msg|
                msg.end_to_end_id = @end_to_end_id
                if same_direction?(msg)
                    msg.source = @originating_endpoint.name
                    msg.destination = @destination_endpoint.name
                else
                    msg.source = @destination_endpoint.name
                    msg.destination = @originating_endpoint.name
                end
            end
        end
    end
end