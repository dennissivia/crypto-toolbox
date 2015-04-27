require 'socket'

module Analyzers
  module CbcMac
    module VariableLength
      module Oracles
        class Tcp
          def initialize(mac_host = '54.165.60.84', mac_port = 81, verify_host = '54.165.60.84', verify_port = 82)
            @mac_host      = mac_host
            @mac_port      = mac_port
            @verify_host   = verify_host
            @verify_port   = verify_port
            @mac_socket    = nil
            @verify_socket = nil
          end
          def connect
            @mac_socket    = TCPSocket.open(@mac_host,@mac_port)
            @verify_socket = TCPSocket.open(@verify_host,@verify_port)
            #puts "Connected to server successfully."
          end
          def disconnect
            @verify_socket.close if @verfiy_socket
            @mac_socket.close    if @mac_socket
          end

          def mac(message)
            connect unless @mac_socket
            packet = ( message.length.to_crypt_buffer + message + [0] ).chars.join("")

            @mac_socket.write(packet)
            @mac_socket.read(16)
          end

          def verify(message,tag)
            connect unless @verify_socket

            # Message-length + message-chars + tag-chars + 0
            # NOTE: check why chars instead of bytes.map does not work here
            packet = (message.length.to_crypt_buffer + message + tag.split("") + [0] ).bytes.map(&:chr).join("")
            
            @verify_socket.write(packet)
            @verify_socket.read(2).to_i
          end

          
        end
      end
    end
  end
end





