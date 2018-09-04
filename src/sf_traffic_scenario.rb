require 'sf_html_writer'

class TrafficScenario
    attr_accessor :snapshots, :service_events

    def initialize(messages, out_fname, base_dir)
        @messages = messages
        @html_writer = HtmlWriter.new(base_dir, out_fname)
    end

    def process
        extract_dialogs
        calculate_dialog_endpoints
        calculate_message_endpoints
        calculate_service_event_nodes
        modify_message_captions
        @html_writer.write(@messages, @snapshots, @service_events)
    end

private
    def calculate_service_event_nodes
        unless service_events.nil?
            service_events.each do |event|
                dialog = @dialogs[event.trigger_message.call_id]
                if dialog.nil?
                    next
                end
                if dialog.same_direction?(event.trigger_message)
                    event.node = dialog.mtas_endpoint.name
                else
                    event.node = dialog.remote_endpoint.name
                end
            end
        end
    end
    
    def extract_dialogs
        @dialogs = Hash.new
        @dialog_array = []
        @tcap_dialogs = []
        @messages.each do |message|
            if message.sip?
                call_id = message.call_id
                dialog = @dialogs[call_id]
                if dialog.nil?
                    dialog = Sip::Dialog.new
                    @dialogs[call_id] = dialog
                    @dialog_array << dialog
                end
                dialog.add_message(message)
            elsif message.tcap?
                added_to_dialog = false
                @tcap_dialogs.each do |dialog|
                    added_to_dialog = dialog.add_message?(message)
                    if added_to_dialog
                        break
                    end
                end
                unless added_to_dialog
                    @tcap_dialogs << Tcap::Dialog.new(message)
                end
            end
        end
        # @dialog_array.each do |dialog|
            # dialog.check_if_incomplete
        # end
        # remove_incomplete_dialogs
        @dialog_array.each do |dialog|
            dialog.calculate_icid_and_sdp_connection
            dialog.update_end_to_end_id
        end
    end

    def calculate_dialog_endpoints
        @dialog_array.each do |dialog|
            dialog.calculate_endpoints()
        end
        correlate_dialog_endpoints
        if $options[:merge_users]
            merge_remote_endpoints
        end
        @tcap_dialogs.each do |dialog|
            dialog.calculate_endpoints(@messages, @dialogs)
        end
        if $debug
            puts 'Dialogs:'
            @dialog_array.each do |dialog|
                puts dialog.to_s
            end
        end
    end

    # Adjust dialog endpoints based on correlation between previous dialogs.
    def correlate_dialog_endpoints
        @dialog_array.each_with_index do |dialog, i|
            next if i == 0
            @dialog_array[0..i-1].reverse.each do |d|
                if !dialog.icid_value.nil? && !d.icid_value.nil?
                    if dialog.icid_value == d.icid_value
                        change_endpoint(dialog, d)
                    end
                    break
                end
                if !dialog.from_sdp_connection.nil? && !d.from_sdp_connection.nil? && dialog.from_sdp_connection == d.from_sdp_connection
                    change_endpoint(dialog, d)
                    break
                end
                if !dialog.to_sdp_connection.nil? && !d.to_sdp_connection.nil? && dialog.to_sdp_connection == d.to_sdp_connection
                    change_endpoint(dialog, d)
                    break
                end
            end
        end
    end

    def change_endpoint(dialog, d)
        if !d.initial_request.nil? #&& dialog.initial_request.incoming?
            if !dialog.initial_request.nil? #&& dialog.initial_request.outgoing?
                d.mtas_endpoint.name.match(/(?:(Orig|Term) )?(?:(TEL|SCC|ST|SDS) )?AS(?: (.+))?/)
                session_side = $1
                as_type = $2
                served_user = $3
                if dialog.mtas_to_mtas?
                    dialog.remote_endpoint.name.match(/(?:(Orig|Term) )?(?:(TEL|SCC|ST|SDS) )?AS(?: (.+))?/)
                    if !$1.nil?
                        if session_side.nil?
                            session_side = $1
                        elsif session_side != $1
                            return false
                        end
                    end
                    if !$2.nil?
                        if as_type.nil?
                            as_type = $2
                        elsif as_type != $2
                            return false
                        end
                    end
                    if !$3.nil? 
                        if served_user.nil?
                            served_user = $3
                        elsif served_user != $3
                            return false
                        end
                    end
                    d.mtas_endpoint.set_mtas_name(session_side, as_type, served_user)
                    dialog.remote_endpoint = d.mtas_endpoint
                    return true
                else
                    if dialog.initial_request.outgoing?
                        dialog.mtas_endpoint.name.match(/(?:(Orig|Term) )?(?:(TEL|SCC|ST|SDS) )?AS(?: (.+))?/)
                        if !$1.nil?
                            if session_side.nil?
                                session_side = $1
                            elsif session_side != $1
                                return false
                            end
                        end
                        if !$2.nil?
                            if as_type.nil?
                                as_type = $2
                            elsif as_type != $2
                                return false
                            end
                        end
                        if !$3.nil? 
                            if served_user.nil?
                                served_user = $3
                            elsif served_user != $3
                                return false
                            end
                        end
                        d.mtas_endpoint.set_mtas_name(session_side, as_type, served_user)
                        dialog.mtas_endpoint = d.mtas_endpoint
                        return true
                    end
                end 
            end
        end
        return false
    end

    def merge_remote_endpoints
        @dialog_array.each do |dialog|
            @dialog_array.each do |d|
                if dialog.remote_endpoint.name.include?(d.remote_endpoint.name)
                    d.remote_endpoint.name = dialog.remote_endpoint.name
                end
            end
        end
    end

    OCS = 'OCS'
    CDF = 'CDF'
    HSS = 'HSS'
    MRFP = 'MRFP'

    def calculate_message_endpoints
        dialog = nil
        @tcap_dialogs.each do |tcap_dialog|
            tcap_dialog.set_message_endpoints
        end
        @messages.each_with_index do |message, i|
            if message.sip?
                next if message.duplicate
                dialog = @dialogs[message.call_id]
                if dialog.mtas_to_mtas?
                    if dialog.same_direction?(message)
                        message.source = dialog.remote_endpoint.name
                        message.destination = dialog.mtas_endpoint.name
                    else
                        message.source = dialog.mtas_endpoint.name
                        message.destination = dialog.remote_endpoint.name
                    end
                elsif message.incoming?
                    message.source = dialog.remote_endpoint.name
                    message.destination = dialog.mtas_endpoint.name
                else
                    message.source = dialog.mtas_endpoint.name
                    message.destination = dialog.remote_endpoint.name
                end
            elsif !dialog.nil? && !message.tcap?
                remote_endpoint = ''
                mtas_endpoint = dialog.mtas_endpoint.name
                message.end_to_end_id = dialog.end_to_end_id
                if message.diameter?
                    if message.application == 'Sh'
                        remote_endpoint = HSS
                    elsif message.application == 'Ro'
                        remote_endpoint = OCS
                    elsif message.application == 'Rf'
                        remote_endpoint = CDF
                    end
                elsif message.megaco?
                    remote_endpoint = MRFP
                    if message.reply?
                        @messages[0..i-1].reverse.each do |msg| # Search for request
                            if msg.megaco? && msg.request? && msg.transaction_id == message.transaction_id
                                if msg.outgoing?
                                    mtas_endpoint = msg.source
                                else
                                    mtas_endpoint = msg.destination
                                end
                                break
                            end
                        end
                    end
                else
                    next
                end
                if message.direction == :incoming
                    message.source = remote_endpoint
                    message.destination = mtas_endpoint
                else
                    message.source = mtas_endpoint
                    message.destination = remote_endpoint
                end
            end
        end
    end

    def modify_message_captions
        @messages.each do |message|
            next if !message.sip?
            if message.caption == "INVITE"
                #Add (re) if we find tags in both To: and From:
                if !message.to.nil? && !message.from.nil?
                    if message.to.downcase.include?(";tag=")
                        message.caption = "(re)" + message.caption
                    end
                end
                #Add (empty) if Content-Length is 0
                if !message.data.nil?
                    if message.headers["Content-Length"] == "0"
                        message.caption = "(empty)" + message.caption
                    end
                end
            elsif message.caption == "NOTIFY"
                if !message.headers["Event"].nil?
                    message.headers["Event"].match(/([^;]*)/)
                    if !$1.nil?
                        message.caption += "(" + $1 + ")"
                    end
                end
            end
            if !message.headers["Content-Type"].nil?
                if (!message.headers["Content-Length"].nil? && message.headers["Content-Length"] != "0")
                    if message.headers["Content-Type"].downcase.include?("application/sdp")
                        message.caption = "(sdp)" + message.caption
                    elsif message.headers["Content-Type"].downcase.include?("multipart/mixed")
                        message.caption = "(mixed)" + message.caption
                    end
                end
            end
            unless message.early_dialog_id.nil?
                message.caption = "(d" + message.early_dialog_id.to_s + ")" + message.caption
            end
        end
    end
end


