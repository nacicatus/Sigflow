class ServiceEvent
    attr_accessor :caption, :timestamp, :data, :trigger_message, :node, :last_message 
    
    def initialize(caption, timestamp, data, trigger_message, last_message)
        @caption = caption
        @timestamp = timestamp
        @data = data
        @trigger_message = trigger_message
        @last_message = last_message
        @node = nil
    end
end