
class MessageBase
    attr_accessor :source, :destination, :session_side, :direction, :data, :end_to_end_id, :packet, :timestamp, :snapshot_id, :frame_number, :as_type

    def initialize(direction, protocol, session_side, as_type)
        @direction = direction
        @protocol = protocol
        @session_side = session_side
        @data = ''
        @end_to_end_id = ''
        @timestamp = ''
        @snapshot_id = -1
        @frame_number = nil
        @as_type = as_type
    end

    def sip?
        @protocol == :sip
    end

    def diameter?
        @protocol == :diameter
    end

    def megaco?
        @protocol == :megaco
    end
    
    def tcap?
        @protocol == :tcap
    end

    def incoming?
        @direction == :incoming
    end

    def outgoing?
        @direction == :outgoing
    end

    def to_file(file)
        file.write(@session_side == :orig ? 'Originating' : 'Terminating')
        file.write(',')
        file.write(@direction == :incoming ? 'Incoming' : 'Outgoing')
        file.write(',')
        file.write(@data)
    end

    def to_s
        s = "---------------------------------------------------------\n"
        s << @session_side.to_s
        s << ' ' + @direction.to_s
        s << " message:\n"
        s << "---------------------------------------------------------\n"
        s << @data
    end

    def tcp_ip_info
        return '' if @packet.nil?
        s = "\nSource Address: #{@packet.ip_source}\n"
        s << "Destination Address: #{@packet.ip_destination}\n"
        s << "Transport: #{@packet.transport_protocol}\n"
        s << "Source Port: #{@packet.source_port}\n"
        s << "Destination Port: #{@packet.destination_port}\n"
    end
end


