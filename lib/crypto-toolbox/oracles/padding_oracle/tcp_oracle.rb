module CryptoToolbox
  module Oracles
    module PaddingOracle

      class TcpOracle
        def initialize
          require "socket"

          @hostname  = '54.165.60.84'
          @port      = 80
          @socket    = nil
        end
        def connect
          @socket = TCPSocket.open(@hostname,@port)
        end
        
        def disconnect
          if @socket
            @socket.close
          end
        end
        
        def valid_padding?(input,block_amount)
          ! send_msg(input, block_amount).zero?
        end

        private
        def send_msg(input,block_amount)
          connect unless connected?

          msg = ([block_amount] + input + [0]).map(&:chr).join
          sleep 0.01
          @socket.write(msg)
          @socket.read(2).to_i
        end
        def connected?
          !!@socket
        end
      end

    end
  end
end
