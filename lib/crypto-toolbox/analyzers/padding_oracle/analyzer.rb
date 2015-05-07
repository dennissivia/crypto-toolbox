require 'crypto-toolbox/analyzers/padding_oracle/oracles/http_oracle.rb'
require 'crypto-toolbox/analyzers/padding_oracle/oracles/tcp_oracle.rb'


module Analyzers
  module PaddingOracle
        
    class Analyzer
      class FailedAnalysis < RuntimeError; end
      attr_reader :result
      include ::Utils::Reporting::Console
      
      def initialize(oracle = ::Analyzers::PaddingOracle::Oracles::TcpOracle.new)
        @result      = [ ]
        @oracle      = oracle
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

        # for whatever reason ranges cant be from high to low
        (1..(blocks.length() -1)).reverse_each do |block_index|
          result.unshift analyse_block(blocks,block_index)
        end
        
        report_result(result)
      end


      
      private

      def analyse_block(blocks,block_index)
        block_result = []
        
        # manipulate each byte of the 16 byte block
        1.upto(blocks[block_index -1].length) do |pad_index|
          with_oracle_connection do
            jot("processing byte #{pad_index} in block: #{block_index -1} => #{block_index}",debug: true)
            byte = read_byte(pad_index,block_result,blocks,block_index)
            block_result.unshift byte
          end
        end
        block_result
      end

      def report_result(result)
        jot(CryptBuffer(result.flatten).chars.inspect,debug: false)
        jot("stripping padding!",debug: true)
        jot(CryptBuffer(result.flatten).strip_padding.str,debug: false)
      end

      def with_oracle_connection
        @oracle.connect
        yield
        @oracle.disconnect
      end

      def apply_found_bytes(buf,cur_result,pad_index)
        # first we have to apply all the already found bytes

        # NOTE: to easily xor all already found byte and the current padding value
        # We build up a byte-array with all the known values and "left-pad" them with zeros
        other = ([0] * ( buf.length - cur_result.length)) + cur_result.map{|x| x ^ pad_index }
        # => [0,0,0,...,cur[n] ^ pad_index,... ]
        buf.xor(other)
      end

      # the blocks are:
      # xxxxxxxx xxxxxxxx xxxxxxxx   [..]
      # ^- IV    ^- first ^- second  ...
      def read_byte(pad_index,cur_result,blocks,block_index)
        jot(cur_result.inspect,debug: true)
        
        # apply all the current-result bytes to the block corresponding to <block_index>
        # and store the result in a buffer we will mess with
        forge_buf = apply_found_bytes(blocks[block_index - 1],cur_result,pad_index)
        
        1.upto 256 do |guess|
          input = assemble_oracle_input(forge_buf,blocks,block_index,pad_index,guess)
          
          next if skip?(pad_index,block_index,guess,cur_result)

          return guess if@oracle.valid_padding?(input,block_amount(block_index))
        end

        raise FailedAnalysis, "No padding found... this should neve happen..."
      end
      private

      # include the block after the index, since this
      # is the one effected by our manipulation. ( due to cbc mode )
      def block_amount(index)
        index +1 
      end

      # Create a subset to only send the blocks we still need to decrypt.
      # manipulate the byte with a padding-index and a guess
      # map the crypt buffer array to a flat array of integers ( representing bytes )
      def assemble_oracle_input(buffer,blocks,block_index,pad_index,guess)
        # the bytes from the subset we will send to the padding oracle
        subset = blocks[0,block_index+1]
        subset[block_index -1 ] = buffer.xor_at([guess,pad_index], -1 * pad_index)
        subset.map(&:bytes).flatten
      end
      
      # In case of the first iteration there is a special case to skip:
      # 1) No other blocks have been decrypted yet ( result.empty? )
      # 2) No bytes of the current block have been processed yet ( block_result_empty? )
      # 3) guess xor pad-index does not modify anything ( eq zero )
      # => This would leed to the original ciphertext without any modification beeing sent
      def skip?(pad_index,block_index,guess,block_result)
        result.empty? && block_result.empty? && (guess ^ pad_index).zero?
      end
      
    end
  end
end


