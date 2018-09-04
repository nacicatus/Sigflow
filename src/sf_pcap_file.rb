
require 'set'
require 'sf_diameter'
require 'sf_sip'
require 'sf_megaco'
require 'sf_tcap'
require 'rexml/document'
include REXML

module PcapFile
extend PcapFile

    ORIGINATING_PORT = 5082
    TERMINATING_PORT = 5083
    TERMINATING_UNREG_PORT = 5084
    ORIGINATING_UNREG_PORT = 5087
    SCC_ORIGINATING_PORT = 5160
    SCC_ORIGINATING_UNREG_PORT = 5161
    SCC_TERMINATING_PORT = 5162
    SCC_TERMINATING_UNREG_PORT = 5163
    CONFERENCE_PORT = 5060
    ST_PORT = 5090

    SIP_PORTS = [
        ORIGINATING_PORT,
        TERMINATING_PORT,
        TERMINATING_UNREG_PORT,
        ORIGINATING_UNREG_PORT,
        SCC_ORIGINATING_PORT,
        SCC_ORIGINATING_UNREG_PORT,
        SCC_TERMINATING_PORT,
        SCC_TERMINATING_UNREG_PORT,
        ST_PORT,
        5060,
        5061,
        6001 # Used as SIP port sometimes. Can't hurt to try decode it as SIP?
    ]

    DIAMETER_PORTS = [3868, 3869, 3870, 3871, 3872, 3873, 3874, 3875, 3888]

    FAULTY_WIRESHARK_VERSIONS = ['wireshark/1.4.0rc2', 'wireshark/1.8.6']
    SUPPORTED_WIRESHARK_VERSIONS = ['EWshark/R1.17']

    @@users = Set.new

    def read(fname)
        check_wireshark_version
        get_mtas_ip_addresses(fname)
        invoke_tshark(fname)
        return read_pdml
    end

    def users
        @@users
    end
    
    def session_side_from_port(port)
        case port
        when ORIGINATING_PORT, SCC_ORIGINATING_PORT, ORIGINATING_UNREG_PORT, SCC_ORIGINATING_UNREG_PORT
            return :orig
        when TERMINATING_PORT, TERMINATING_UNREG_PORT, SCC_TERMINATING_PORT, SCC_TERMINATING_UNREG_PORT
            return :term
        else
            return nil
        end
    end

    def as_type_from_port(port)
        case port
        when ORIGINATING_PORT, ORIGINATING_UNREG_PORT, TERMINATING_PORT, TERMINATING_UNREG_PORT
            return :tel
        when SCC_ORIGINATING_PORT, SCC_ORIGINATING_UNREG_PORT, SCC_TERMINATING_PORT, SCC_TERMINATING_UNREG_PORT
            return :scc
        when ST_PORT
            return :st
        else
            return nil
        end
    end

private
    def check_wireshark_version
        FAULTY_WIRESHARK_VERSIONS.each do |faulty_wireshark|
            if ENV['PATH'].include?(faulty_wireshark)
                puts "-------------------------------------------------------------------------------"
                puts " ERROR: Faulty Wireshark version detected: #{faulty_wireshark}"
                puts " Please unload it and load #{supported_wireshark} by typing:"
                puts " module remove #{faulty_wireshark}; module add #{supported_wireshark}"
                puts "-------------------------------------------------------------------------------\n"
                exit(0)
            end
        end
    end

    def get_mtas_ip_addresses(fname)
        @mtas_addresses = []
        user_supplied_addresses = $options[:mtas_ip_addresses]
        if user_supplied_addresses.nil?
            if !get_mtas_addresses_from_pcap(fname)
                puts "Could not find any MTAS ip-addresses using new method, trying old method..."
                # If the new method fails we try the old one.
                get_mtas_addresses_from_pcap_old(fname)
            end
        else
            user_supplied_addresses.split(',').each do |ip_address|
                @mtas_addresses << ip_address.downcase
            end
            @mtas_sip_addresses = @mtas_diameter_addresses = @mtas_addresses
        end
        address_info = "IP address(es): "
        @mtas_addresses.each do |address|
            address_info << address + ' '
        end
        puts address_info
    end

    # This is a new method for calculating MTAS IP addresses. The old method checked for port 5090 which is not
    # always unique to mtas. This new method still checks unique ports (excluding 5090) and also tries to find
    # IP addresses without using ports. Instead we use user-agent, p-served-user and call-id headers.
    # Pros: Can find MTAS addresses no matter what port is used; 5060 or 5090 for example.
    # Cons: This doesn't find ST MTAS address at port 5090 if there are no p-served-user/user-agent headers.
    # That is why we try the old method if we don't find any MTAS addresses using this method.
    def get_mtas_addresses_from_pcap(fname)
        puts "Finding MTAS IP address..."
        mtas_addresses = Set.new
        mtas_sip_addresses = Set.new
        mtas_diameter_addresses = Set.new

        # Try to find MTAS ip-addresses using unique ports.
        decode_as = ''
        DIAMETER_PORTS.each do |port|
            decode_as += "-d tcp.port==#{port},diameter "
        end
        system("tshark #{decode_as} -nr #{fname} -Y \"!icmp && !icmpv6 && (!diameter || (diameter.cmd.code != 280 && diameter.cmd.code != 257))\" -T fields -e diameter -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e tcp.dstport -e udp.dstport -E occurrence=l -E separator=/s -E quote=s > mtas_ip_addresses")
        port_regex_str = ''
        mtas_dest_ports = SIP_PORTS[0..-5] # Exclude 5060, 5061, 5090 and 6001 since they are not unique to MTAS.
        mtas_dest_ports << DIAMETER_PORTS
        mtas_dest_ports.flatten!
        mtas_dest_ports.each_with_index do |port, i|
            port_regex_str << port.to_s
            port_regex_str << '|' if i < mtas_dest_ports.length - 1
        end
        # Sometimes there are both IPv4 and IPv6 addresses.
        mtas_regex_both_ip_versions = /(?:'(.+)'\s+)?'(.+)'\s+'(.+)'\s+'(.+)'\s+'(.+)'\s+'(#{port_regex_str})'/
        mtas_regex = /(?:'(.+)'\s+)?'(.+)'\s+'(.+)'\s+'(#{port_regex_str})'/
        File.readlines('mtas_ip_addresses').each do |line|
            if line =~ mtas_regex_both_ip_versions
                diameter = $1
                ip_source = $3
                ip_dest = $5
                port = $6.to_i
            elsif line =~ mtas_regex
                diameter = $1
                ip_source = $2
                ip_dest = $3
                port = $4.to_i
            else
                next
            end
            if SIP_PORTS.include?(port)
                mtas_sip_addresses << ip_dest
                mtas_addresses << ip_dest
            elsif diameter == "diameter"
                mtas_diameter_addresses << ip_source
                mtas_addresses << ip_source
            end
        end
        
        # Try to find MTAS IP addresses without using ports. Instead use p-served-user, user-agent and call-id.
        mtas_call_ids = Set.new # We need to check call-id for when orig/term has different IP addresses.
        system("tshark -nr #{fname} -Y \"sip\" -T fields -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e sip.P-Served-User -e sip.User-Agent -e sip.Call-ID -E occurrence=l -E separator=/s -E quote=s > mtas_ip_addresses")

        mtas_regex_both_ip_versions = /'(.+)'\s+'(.+)'\s+'(.+)'\s+'(.+)'\s+'(.+)'\s+'(.+)'\s+'(.+)'/
        mtas_regex = /'(.+)'\s+'(.+)'\s+'(.+)'\s+'(.+)'\s+'(.+)'/
        file_lines = File.readlines('mtas_ip_addresses')
        file_lines.each do |line|
            if line =~ mtas_regex_both_ip_versions
                ip_source = $2
                ip_dest = $4
                p_served_user = $5
                user_agent = $6
                call_id = $7
            elsif line =~ mtas_regex
                ip_source = $1
                ip_dest = $2
                p_served_user = $3
                user_agent = $4
                call_id = $5
            else
                next
            end
            if user_agent.downcase.include?("ericsson mtas") && p_served_user.downcase.include?("sescase=orig") && !mtas_sip_addresses.include?(ip_dest) && !mtas_call_ids.include?(call_id)
                mtas_sip_addresses << ip_source
                mtas_addresses << ip_source
                mtas_call_ids << call_id
                break
            end
        end
        file_lines.each do |line|
            if line =~ mtas_regex_both_ip_versions
                ip_source = $2
                ip_dest = $4
                p_served_user = $5
                user_agent = $6
                call_id = $7
            elsif line =~ mtas_regex
                ip_source = $1
                ip_dest = $2
                p_served_user = $3
                user_agent = $4
                call_id = $5
            else
                next
            end
            if user_agent.downcase.include?("ericsson mtas") && p_served_user.downcase.include?("sescase=term") && !mtas_sip_addresses.include?(ip_dest) && !mtas_call_ids.include?(call_id)
                mtas_sip_addresses << ip_source
                mtas_addresses << ip_source
                mtas_call_ids << call_id
            end
        end

        if mtas_sip_addresses.empty?
            return false
        end
        # Find MTAS addresses using megaco messages.
        system("tshark -nr #{fname} -Y \"megaco\" -T fields -e ip.src -e megaco.termid -E occurrence=l -E separator=/s -E quote=s > mtas_ip_addresses")
        File.readlines('mtas_ip_addresses').each do |line|
            if line =~ /'(.+)'\s+'(.+)'/
                ip_source = $1
                termid = $2
                if termid =~ /rtp\/.+\/\$/
                    mtas_addresses << ip_source
                end
            end
        end
        @mtas_addresses = mtas_addresses.to_a
        @mtas_sip_addresses = mtas_sip_addresses.to_a
        @mtas_diameter_addresses = mtas_diameter_addresses.to_a
        return true
    end

    def get_mtas_addresses_from_pcap_old(fname)
        puts "Finding MTAS IP address..."
        mtas_addresses = Set.new
        mtas_sip_addresses = Set.new
        mtas_diameter_addresses = Set.new
        system("tshark -nr #{fname} -Y \"!icmp && !icmpv6\" -T fields -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e tcp.dstport -e udp.dstport -E occurrence=l -E separator=/s -E quote=s > mtas_ip_addresses")
        port_regex_str = ''
        mtas_dest_ports = SIP_PORTS[0..-4] # Exclude 5060 and 5061 since they are not unique to MTAS.
        mtas_dest_ports << DIAMETER_PORTS
        mtas_dest_ports.flatten!
        mtas_dest_ports.each_with_index do |port, i|
            port_regex_str << port.to_s
            port_regex_str << '|' if i < mtas_dest_ports.length - 1
        end
        mtas_regex_both_ip_versions = /'(.+)'\s+'(.+)'\s+'(.+)'\s+'(.+)'\s+'(#{port_regex_str})'/
        mtas_regex = /'(.+)'\s+'(.+)'\s+'(#{port_regex_str})'/
        File.readlines('mtas_ip_addresses').each do |line|
            if line =~ mtas_regex_both_ip_versions
                ip_source = $2
                ip_dest = $4
                port = $5.to_i
            elsif line =~ mtas_regex
                ip_source = $1
                ip_dest = $2
                port = $3.to_i
            else
                next
            end
            if SIP_PORTS.include?(port)
                mtas_sip_addresses << ip_dest
                mtas_addresses << ip_dest
            else
                mtas_diameter_addresses << ip_source
                mtas_addresses << ip_source
            end
        end
        if mtas_sip_addresses.empty?
            puts "Could not figure out MTAS IP address(es). Please run with option '-a' to specify MTAS address."
            exit(0)
        end
        @mtas_addresses = mtas_addresses.to_a
        @mtas_sip_addresses = mtas_sip_addresses.to_a
        @mtas_diameter_addresses = mtas_diameter_addresses.to_a
    end

    def invoke_tshark(fname)
        decode_as = ''
        SIP_PORTS.each do |port|
            decode_as += "-d tcp.port==#{port},sip -d udp.port==#{port},sip "
        end
        DIAMETER_PORTS.each do |port|
            decode_as += "-d tcp.port==#{port},diameter "
        end

        eth_filter = ''
        if $options[:frame_interval]
            start_frame = $options[:frame_interval_first]
            end_frame = $options[:frame_interval_last]
            eth_filter << "(frame.number > #{start_frame} && frame.number < #{end_frame}) && "
        end

        ip_filter = '('
        @mtas_addresses.each_with_index do |mtas_address, i|
            if mtas_address.include?(':')
                ip_filter << "ipv6.addr == #{mtas_address}"
            else
                ip_filter << "ip.addr == #{mtas_address}"
            end
            ip_filter << ' || ' if i < @mtas_addresses.length - 1
        end
        ip_filter << ')'
        
        sip_ip_filter = '('
        @mtas_sip_addresses.each_with_index do |mtas_address, i|
            if mtas_address.include?(':')
                sip_ip_filter << "ipv6.addr == #{mtas_address}"
            else
                sip_ip_filter << "ip.addr == #{mtas_address}"
            end
            sip_ip_filter << ' || ' if i < @mtas_sip_addresses.length - 1
        end
        sip_ip_filter << ')'

        sip_filter = '(sip'
        sip_filter << " && #{sip_ip_filter}"
        user = $options[:user]
        unless user.nil?
            sip_filter << " && (sip.to.user contains \"#{user}\" || sip.from.user contains \"#{user}\")"
        end
        sip_filter << ')'
        
        diameter_filter = ''
        if ($options[:charging] || $options[:sh] || $options[:hidden_messages])
            diameter_filter = ' || (diameter && diameter.cmd.code != 280 && diameter.cmd.code != 257)'
        end
        
        megaco_filter = ''
        if ($options[:megaco] || $options[:hidden_messages])
            megaco_filter = ' || megaco'
        end
        
        tcap_filter = ''
        if ($options[:tcap] || $options[:hidden_messages])
            tcap_filter = ' || tcap || camel || inap'
        end
        
        filter = "#{eth_filter}((#{ip_filter} && (#{sip_filter}#{diameter_filter}#{megaco_filter}))#{tcap_filter})"
        cmd = "tshark -o tcap.ssn:1-254 -o camel.tcap.ssn:1-254 -o inap.ssn:1-254 #{decode_as} -Y \"#{filter}\" -r #{fname} -T pdml > out.xml"
        puts "Reading PCAP file..."
        system(cmd)
    end

    class TcpIpData
        attr_accessor :ip_source, :ip_destination, :id, :length, :transport_protocol, :source_port, :destination_port
    end

    def read_pdml
        messages = []
        prev_packet = nil
        puts "Parsing PDML file. This may take a while..."
        doc = read_xml_doc
        num_packets = get_number_of_packets(doc)
        packet_index = 0
        doc.elements.each("pdml/packet") do |packet_element|
            packet_index += 1
            $stdout.write "\rProcessing packets: #{(packet_index * 100) / num_packets}% "
            $stdout.flush
            message = nil
            begin
                protocols = packet_element.elements

                fields = get_protocol_fields(protocols, 'frame')
                timestamp = get_field_show_value(fields, 'frame.time_relative')[0...-3]
                frame_number = get_field_show_value(fields, 'frame.number')

                packet = TcpIpData.new
                fields = get_protocol_fields(protocols, 'ip')
                unless fields.nil?
                    packet.ip_source = get_field_show_value(fields, 'ip.src')
                    packet.ip_destination = get_field_show_value(fields, 'ip.dst')
                    packet.id = get_field_show_value(fields, 'ip.id')
                    packet.length = get_field_show_value(fields, 'ip.len')
                    if !prev_packet.nil?
                        if prev_packet.id == packet.id && prev_packet.length == packet.length
                            next
                        end
                    end
                end

                fields = get_protocol_fields(protocols, 'ipv6')
                unless fields.nil?
                    packet.ip_source = get_field_show_value(fields, 'ipv6.src')
                    packet.ip_destination = get_field_show_value(fields, 'ipv6.dst')
                end

                fields = get_protocol_fields(protocols, 'sctp')
                unless fields.nil?
                    packet.transport_protocol = 'SCTP'
                    packet.source_port = get_field_show_value(fields, 'sctp.srcport').to_i
                    packet.destination_port = get_field_show_value(fields, 'sctp.dstport').to_i
                end

                fields = get_protocol_fields(protocols, 'tcp')
                unless fields.nil?
                    packet.transport_protocol = 'TCP'
                    packet.source_port = get_field_show_value(fields, 'tcp.srcport').to_i
                    packet.destination_port = get_field_show_value(fields, 'tcp.dstport').to_i
                end

                fields = get_protocol_fields(protocols, 'udp')
                unless fields.nil?
                    packet.transport_protocol = 'UDP'
                    packet.source_port = get_field_show_value(fields, 'udp.srcport').to_i
                    packet.destination_port = get_field_show_value(fields, 'udp.dstport').to_i
                end

                message = extract_message(protocols, packet)
                unless message.nil?
                    puts message.data.lines.first if $debug
                    message.packet = packet
                    message.timestamp = timestamp
                    message.frame_number = frame_number
                    messages << message
                end
                prev_packet = packet
            rescue Exception => e
                puts 'Skipping packet, error while reading PDML file: ' + e.message
            end
        end
        return remove_sip_duplicates(messages)
    end

    def supported_wireshark
        SUPPORTED_WIRESHARK_VERSIONS.last
    end

    def read_xml_doc
        xml = File.read("out.xml")
        if xml.rindex("</pdml>\n").nil?
            # Correct for missing end-tag bug in tshark.
            xml += '</pdml>'
        end
        begin
          return Document.new(xml)
        rescue Exception => e
            puts "-------------------------------------------------------------------------------"
            puts " ERROR: Failed to read XML. Check that the only loaded Wireshark version is:"
            puts " #{supported_wireshark}"
            puts ""
            puts " Please unload your other Wireshark versions and load #{supported_wireshark}:"
            puts " First type \"module list\" and for each loaded Wireshark version, type"
            puts " \"module remove <loaded wireshark>\". Then type \"module add #{supported_wireshark}\""
            puts "-------------------------------------------------------------------------------\n"
            exit(0)
        end
    end

    def get_number_of_packets(doc)
        num_packets = 0
        doc.elements.each("pdml/packet") do |pkt|
            num_packets += 1
        end
        return num_packets
    end

    def get_field_show_value(fields, name)
        field = fields["field[@name='#{name}']"]
        unless field.nil?
            return field.attributes["show"]
        end
    end

    def get_field_showname_value(fields, name)
        field = fields["field[@name='#{name}']"]
        unless field.nil?
            return field.attributes["showname"]
        end
    end

    def get_protocol_fields(protocols, protocol)
        proto = protocols["proto[@name='#{protocol}']"]
        unless proto.nil?
            return proto.elements
        else
            return nil
        end
    end

    def get_direction(packet, mtas_addresses)
        if mtas_addresses.include?(packet.ip_destination)
            return :incoming
        elsif mtas_addresses.include?(packet.ip_source)
            return :outgoing
        else
            return nil
        end
    end

    def extract_message(protocols, packet)
        direction = nil
        fields = get_protocol_fields(protocols, 'sip')
        unless fields.nil?
            direction = get_direction(packet, @mtas_sip_addresses)
            session_side = nil
            as_type = nil
            if direction == :incoming
                session_side = session_side_from_port(packet.destination_port)
                as_type = as_type_from_port(packet.destination_port)
            end
            message_data = get_sip_message_data(fields)
            message = Sip::Message.create(message_data, direction, session_side, as_type)
            if !sip_message_relevant?(message)
                message = nil
            end
            return message
        end
        if $options[:charging] || $options[:sh] || $options[:hidden_messages]
            fields = get_protocol_fields(protocols, 'diameter')
            unless fields.nil?
                direction = get_direction(packet, @mtas_addresses)
                return extract_diameter_message(fields, direction)
            end
        end
        if $options[:megaco] || $options[:hidden_messages]
            fields = get_protocol_fields(protocols, 'megaco')
            unless fields.nil?
                direction = get_direction(packet, @mtas_addresses)
                return extract_megaco_message(fields, direction)
            end
        end
        if $options[:tcap] || $options[:hidden_messages]
            fields = get_protocol_fields(protocols, 'tcap')
            unless fields.nil?
                return extract_tcap_message(fields, protocols)
            end
        end
    end

    def get_sip_message_data(fields)
        first_line = ''
        request_line_field = fields["field[@name='sip.Request-Line']"]
        if request_line_field.nil?
            first_line = get_field_show_value(fields, 'sip.Status-Line')
        else
            first_line = get_field_show_value(fields, 'sip.Request-Line')
        end
        first_line << "\r\n"
        rest_of_msg = get_field_show_value(fields, 'sip.msg_hdr')
        rest_of_msg.gsub!(/\\"/, '"')
        rest_of_msg.gsub!(/\\x0d\\x0a/, "\r\n")
        # "\x0a" should also be replaced by newline.
        rest_of_msg.gsub!(/\\x0a/, "\r\n")
        return first_line + rest_of_msg
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
            method = sip_message.method
        else
            status_code = sip_message.status_code.to_i
            method = ''
        end
        eval(filter)
    end
    
    def write_elements(message_data, element, depth)
        indentation = ''
        depth.times do
            indentation += "  "
        end
        if element.attributes['showname'].nil?
            unless element.attributes['show'].nil?
                message_data << indentation + element.attributes['show'] + "\n"
            end
        else
            message_data << indentation + element.attributes['showname'] + "\n"
        end
        if element.has_elements?
            element.elements.each do |e|
                write_elements(message_data, e, depth + 1)
            end
        end
    end
    
    def extract_tcap_message(tcap_fields, protocols)
        message_data = "#{protocols["proto[@name='tcap']"].attributes['showname']}\n"
        primitive = tcap_fields.to_a.first
        return nil if primitive.nil?
        message_data << "  #{primitive.attributes['showname']}\n"
        primitive.elements.each do |element|
            if element.attributes['name'] == "tcap.components"
                message_data << "    #{element.attributes['showname']}\n"
            else
                write_elements(message_data, element, 2)
            end
        end
        found_tcap = false
        protocols.to_a.each do |protocol|
            if protocol.attributes['name'] == "tcap"
                found_tcap = true
                next
            end
            if found_tcap
                write_elements(message_data, protocol, 0)
            end
        end
        return Tcap::Message.create(message_data, primitive.attributes['showname'])
    end

    def extract_diameter_message(fields, direction)
        message_data = get_field_showname_value(fields, 'diameter.cmd.code') + "\n"
        command = get_field_show_value(fields, 'diameter.cmd.code').to_i
        flag_fields = fields["field[@name='diameter.flags']"].elements
        message_data << get_field_showname_value(flag_fields, 'diameter.flags.request') + "\n"
        request_flag = get_field_show_value(flag_fields, 'diameter.flags.request').to_i
        message_data << get_field_showname_value(fields, 'diameter.applicationId') + "\n"
        application = get_field_show_value(fields, 'diameter.applicationId').to_i
        message_data << get_field_showname_value(fields, 'diameter.hopbyhopid') + "\n"
        message_data << get_field_showname_value(fields, 'diameter.endtoendid') + "\n"
        get_avps(fields, message_data, 0)
        return Diameter::Message.create(message_data, direction, command, request_flag, application)
    end

    def get_avps(fields, message, indent)
        fields.each do |field|
            if field.attributes['name'] == 'diameter.avp'
                indent_message(message, indent)
                avp_data = field.attributes['showname'] + "\n"
                message << avp_data
                field.elements.each do |child_field|
                    if child_field.elements.nil? || child_field.attributes['name'] == 'diameter.avp.flags'
                        next
                    elsif child_field.attributes['name'] == 'diameter.User-Data'
                        get_user_data(child_field.attributes['show'],  message)
                    else
                        get_avps(child_field.elements, message, indent + 3)
                    end
                end
            end
        end
    end

    def indent_message(message, indent)
        indent.times do
            message << ' '
        end
    end

    def get_user_data(user_data_hex, message)
        begin
            user_data_ascii = hex_to_ascii(user_data_hex)
            xml_doc = Document.new(user_data_ascii)
            formatter = REXML::Formatters::Pretty.new(3)
            formatter.compact = true
            formatter.write(xml_doc.root, message)
        rescue Exception => e
            message << "   Error in XML: #{e.message}"
        end
    end

    def hex_to_ascii(hex)
        byte_list = hex.scan(/(..):/)
        char_list = byte_list.map do |byte|
            byte.first.to_i(16).chr
        end
        return char_list.join + '>'
    end

    def extract_megaco_message(fields, direction)
        msg_type = ''
        transaction_id = ''
        fields.each do |field|
            child_fields = field.elements
            unless child_fields.nil?
                msg_type_tmp = get_field_show_value(child_fields, 'megaco.transaction')
                transaction_id_tmp = get_field_show_value(child_fields, 'megaco.transid')
                msg_type = msg_type_tmp unless msg_type_tmp.nil?
                transaction_id = transaction_id_tmp unless transaction_id_tmp.nil?
            end
            if field.attributes['show'].include?('RAW text output')
                # Next field is the text field that contains message data.
                text_field_index = fields.index(field) + 1
                unless text_field_index == -1
                    message_data = ''
                    for i in text_field_index..fields.size
                        message_data += fields[i].attributes['show'] + "\r\n"
                    end
                    return Megaco::Message.new(message_data, direction, msg_type, transaction_id)
                end
                return nil
            end
        end
    end

    def remove_sip_duplicates(messages)
        duplicate_messages = []
        messages.each_with_index do |message, i|
            next if !message.sip?
            messages.drop(i + 1).each do |cmp_message|
                next if !cmp_message.sip?
                if (message.packet.ip_source == cmp_message.packet.ip_source &&
                    message.packet.ip_destination == cmp_message.packet.ip_destination &&
                    message.packet.transport_protocol == cmp_message.packet.transport_protocol &&
                    message.packet.source_port == cmp_message.packet.source_port &&
                    message.packet.destination_port == cmp_message.packet.destination_port &&
                    message.data == cmp_message.data)

                    difference_time = message.timestamp.to_f - cmp_message.timestamp.to_f
                    if difference_time.abs < 0.005 # If the timestamps differ by less than 5 ms we assume it's a duplicate and not a resend.
                        if difference_time > 0     # Message comes after cmp_message in time.
                            duplicate_messages.push message
                        else
                            duplicate_messages.push cmp_message
                        end
                    end
                end
            end
        end
        messages -= duplicate_messages
        return messages
    end
end

