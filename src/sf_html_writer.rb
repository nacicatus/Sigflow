require 'cgi'

class HtmlWriter
    def initialize(base_dir, out_fname)
        @base_dir = base_dir
        @out_fname = out_fname.split(/\/|\\/).last
        @out_html_dir = @out_fname + '-html'
    end

    def write(messages, snapshots, service_events)
        Dir::mkdir(@out_html_dir) unless File.exists?(@out_html_dir)
        write_sequence_file(messages, snapshots, service_events)
        write_message_files(messages, service_events)
        unless snapshots.nil?
            write_snapshot_files(snapshots)
        end
        write_index_file
    end

private
    def write_index_file
        html_fname = @out_fname + '.html'
        html = File.read(@base_dir + 'html/index_template.html')
        File.open(html_fname, 'w') do |html_file|
            html.gsub!(/\#sequence_link/, @out_html_dir + '/sequence.html')
            html.gsub!(/\#message_link/, @out_html_dir + '/message0.html')
            html_file.write(html)
        end
        puts "Generated sequence diagram:\nfirefox " + html_fname + " &"
    end

    def write_sequence_file(messages, snapshots, service_events)
        html_fname = @out_html_dir + '/sequence.html'
        html = File.read(@base_dir + 'html/sequence_template.html')
        File.open(html_fname, 'w') do |html_file|
            if $options[:dark]
                html.gsub!(/\#bg_color/, 'rgb(55,55,55)')
            else
                html.gsub!(/\#bg_color/, 'rgb(230,230,230)')
            end
            html.gsub!(/DARK/, $options[:dark].to_s)
            message_array_str, hidden_messages = encode_message_array_str(messages, service_events)
            html.gsub!(/\/\/ Messages go here/, message_array_str)
            unless snapshots.nil?
                snapshot_array_str = encode_snapshot_array_str(snapshots)
                html.gsub!(/\/\/ Snapshots go here/, snapshot_array_str)
            end
            html.gsub!(/\/\/ Options string go here/, "\"" + $parameters + "\";")
            html.gsub!(/\/\/ Available string go here/, "\"" + hidden_messages + "\";")
            html_file.write(html)
        end
    end
    
    def encode_message_array_str(messages, service_events)
        s = ''
        hidden_megaco = false
        hidden_charging = false
        hidden_sh = false
        hidden_tcap = false
        messages.each_with_index do |message, i|
            if message.source && message.destination
                write_message = true
                if message.megaco?
                    unless $options[:megaco]
                        hidden_megaco = true
                        write_message = false
                    end
                elsif message.diameter?
                    if message.charging?
                        unless $options[:charging]
                            hidden_charging = true
                            write_message = false
                        end
                    elsif message.sh?
                        unless $options[:sh]
                            hidden_sh = true
                            write_message = false
                        end
                    end
                elsif message.tcap?
                    unless $options[:tcap]
                        hidden_tcap = true
                        write_message = false
                    end
                end
                if write_message
                    message_str = "        { source: \"#{message.source}\", "
                    message_str << "destination: \"#{message.destination}\", "
                    message_str << "snapshot_id: \"#{message.snapshot_id}\", "
                    message_str << "timestamp: \"#{message.timestamp}\", "
                    message_str << "end_to_end_id: \'#{message.end_to_end_id}\', " # \' to avoid mess-up when icid-value contains "
                    message_str << "caption: \"#{message.caption}\", "
                    message_str << "tcp_ip: #{message.tcp_ip_info.dump}, "
                    message_str << "text: #{encode(message.text.dump)}, "
                    message_str << "link: \"message#{i}.html\"},\n"
                    s << message_str
                end
            end
            unless service_events.nil?
                service_events.each_with_index do |event, index|
                    if event.last_message == message && event.node
                        message_str = "        { source: \"#{event.node}\", "
                        message_str << "destination: \"#{event.node}\", "
                        message_str << "snapshot_id: \"#{message.snapshot_id}\", "
                        message_str << "timestamp: \"#{event.timestamp}\", "
                        message_str << "end_to_end_id: \'#{message.end_to_end_id}\', "
                        message_str << "caption: \"#{event.caption}\", "
                        message_str << "tcp_ip: \"\", "
                        message_str << "text: \"\", "
                        message_str << "link: \"event#{index}.html\"},\n"
                        s << message_str
                    end
                end
            end
        end
        str = ""
        if hidden_megaco
            str << "Megaco, "
        end
        if hidden_charging
            str << "Charging, "
        end
        if hidden_sh
            str << "Sh, "
        end
        if hidden_tcap
            str << "Cap, " # Currently only tcaps containing camel or inap are included so we write Cap.
        end
        str.chomp!(", ")
        return s, str
    end

    def encode(data)
        data.gsub(/\\\\"/, '\"')
    end

    def encode_snapshot_array_str(snapshots)
        s = ''
        snapshots.each do |snapshot|
            s << "        { id: \"#{snapshot.id}\", link: \"snapshot#{snapshot.id}.html\" },\n"
        end
        return s
    end

    def write_message_files(messages, service_events)
        messages.each_with_index do |message, i|
            if message.source && message.destination
                html = File.read(@base_dir + 'html/message_template.html')
                html_fname = @out_html_dir + "/message#{i}.html"
                File.open(html_fname, 'w') do |html_file|
                    html.gsub!(/\#bg_color/, 'rgb(55,55,55)')
                    html.gsub!(/\#fg_color/, 'rgb(255,255,255)')
                    tcp_ip_info = "Timestamp: " + message.timestamp + (message.frame_number.nil? ? '' : ("\nFrame number: " + message.frame_number)) + message.tcp_ip_info
                    html.gsub!(/TCP_IP/, tcp_ip_info)
                    html.gsub!(/MESSAGE/, CGI.escapeHTML(message.data))
                    html_file.write(html)
                end
            end
            unless service_events.nil?
                service_events.each_with_index do |event, index|
                    if event.last_message == message && event.node
                        html = File.read(@base_dir + 'html/message_template.html')
                        html_fname = @out_html_dir + "/event#{index}.html"
                        File.open(html_fname, 'w') do |html_file|
                            html.gsub!(/\#bg_color/, 'rgb(55,55,55)')
                            html.gsub!(/\#fg_color/, 'rgb(255,255,255)')
                            tcp_ip_info = "Timestamp: " + message.timestamp
                            html.gsub!(/TCP_IP/, tcp_ip_info)
                            html.gsub!(/MESSAGE/, CGI.escapeHTML(event.data))
                            html_file.write(html)
                        end
                    end
                end
            end
        end
    end

    def write_snapshot_files(snapshots)
        template_html = File.read(@base_dir + 'html/snapshot_template.html')
        snapshots.each do |snapshot|
            snapshot_fname = @out_html_dir + '/' + "snapshot#{snapshot.id}.html"
            File.open(snapshot_fname, 'w') do |html_file|
                #html.gsub!(/DARK/, $options[:dark].to_s)
                html = template_html.gsub(/\/\/ Snapshot goes here/, snapshot.javascript_code)
                html_file.write(html)
            end
        end
    end
end

