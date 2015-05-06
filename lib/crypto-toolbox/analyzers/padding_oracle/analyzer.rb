require 'crypto-toolbox/analyzers/padding_oracle/oracles/http_oracle.rb'
require 'crypto-toolbox/analyzers/padding_oracle/oracles/tcp_oracle.rb'


module Analyzers
  module PaddingOracle
        
    class Analyzer
      class FailedAnalysis < RuntimeError; end
      attr_reader :result

      
      def initialize(oracle_class = ::Analyzers::PaddingOracle::Oracles::TcpOracle)
        @result      = [ ]
        @oracle      = oracle_class.new
      end

      # start with the second to last block to manipulate the final block ( cbc xor behaviour )
      # from there on we move to the left until we have used the first block (iv) to decrypt
      # the second blick ( first plain text block )
      #
      # we have to manipulate the block before the one we want to change
      # xxxxxxxxx   xxxxxxxxx     xxxxxxxxxx
      # changing this byte  ^- will change ^- this byte at decryption
      def analyze(cipher)
        blocks = CryptBuffer.from_hex(cipher).chunks_of(16)
        
        (blocks.length - 1).downto(1) do |block_index|
          result_part = []
          # manipulate each byte of the 16 byte block
          1.upto(blocks[block_index -1 ].length) do |pad_index|
            @oracle.connect
            
            jot("processing byte #{pad_index} in block: #{block_index - 1} => #{block_index}",debug: true)
            byte = read_byte(pad_index,result_part,blocks,block_index)
            result_part.unshift byte
            
            @oracle.disconnect
          end
          result.unshift result_part
        end
        jot(CryptBuffer(result.flatten).chars.inspect,debug: false)
        jot("stripping padding!",debug: true)
        jot(CryptBuffer(result.flatten).strip_padding.str,debug: false)
      end


      private
      def jot(message, debug: false)
        if debug == false || ENV["DEBUG_ANALYSIS"]
          puts message
        end
      end
      
      def apply_found_bytes(buf,cur_result,pad_index)
        # first we have to apply all the already found bytes

        # NOTE: to easily xor all already found byte and the current padding value
        # We build up a byte-array with all the known values and "left-pad" them with zeros
        other = ([0] * ( buf.length - cur_result.length)) + cur_result.map{|x| x ^ pad_index }
        # => [0,0,0,...,cur[n] ^ pad_index,... ]
        buf.xor(other)
      end


      def read_byte(pad_index,cur_result,blocks,block_index)
        #iv, first, second, last
        jot(cur_result.inspect,debug: true)
        
        # apply all the current-result bytes to the block corresponding to <block_index>
        # and store the result in a buffer we will mess with
        #
        forge_buf = apply_found_bytes(blocks[block_index - 1],cur_result,pad_index)
        
        1.upto 256 do |guess|
          # the bytes from the subset we will send to the padding oracle
          subset = blocks[0,block_index+1]
          subset[block_index -1 ] = forge_buf.xor_at([guess,pad_index], -1 * pad_index)
 
          input =  subset.map(&:bytes).flatten
          
          # skip the first correct guess on the first iteration of the first block
          # otherwise the resulting ciphertext would eq the original input
          #next if input == blocks.map(&:bytes).flatten
          next if guess == pad_index && guess == 1 && block_index == 2

          block_amount = block_index + 1
          if @oracle.valid_padding?(input,block_amount)
            return guess 
          end

        end

        raise FailedAnalysis, "No padding found... this should neve happen..."
      end

    end
  end
end


