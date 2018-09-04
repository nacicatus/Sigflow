require 'sf_message_base'

module Megaco
    class Message < MessageBase
        attr_reader :transaction_id
        def initialize(message_data, direction, msg_type, transaction_id)
            super(direction, :megaco, nil, nil)
            @data = message_data
            @msg_type, @transaction_id = msg_type, transaction_id
        end

        def caption
            @transaction_id + ' ' + @msg_type
        end

        def request?
            return @msg_type == "Request"
        end

        def reply?
            return @msg_type == "Reply"
        end

        def text
            ''
        end
    end
end
