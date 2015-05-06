#!/usr/bin/env ruby

require 'crypto-toolbox'

module Analyzers
  module PaddingOracle
    module Oracles

      class TcpOracle
        def initialize
          require "socket"
          require_relative "./tcp_oracle.rb"

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
