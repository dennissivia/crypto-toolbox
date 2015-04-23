module Analyzers
  module Utils
    class KeyCandidateMap
      # This class represents a position-index based map of possible values of a key.
      # Example:
      # {
      #  1 => [1,100,22,33]
      #  2 => [2,77,255]
      #  ...
      # n => [22,55,222]
      # }
      include ::Utils::Reporting::Console

      # factory method for easy use
      def self.create(input_buf,keylen)
        new.run(input_buf,keylen)
      end

      # Algorithm
      # 1) for each position of the key: (key_byte_pos)
      # 2) create a stream of all the nth bytes of the keylen
      # 3) xor any possible byte value (guess) with all nth's bytes
      # 4) select those guesses that decipher the nth-byte stream to only english plain ascii chars
      def run(input_buf,keylen)
        candidate_map ={}
        (0..(keylen-1)).each do |key_byte_pos|
    
          # create an array of every nth byte of the input. ( thus a pseudo stream of the nth bytes )
          # 1) create an enumerator of the nth positions. e.g for iteration 0: [0,7,14,...]
          # 2) Next: Map the positions to bytes of the input buffer
          #
          # NOTE: regular implementation without cryptbuffer magic:
          # nth_stream = (key_byte_pos).step(input_buf.bytes.length() -1, keylen).map{|i| input_buf.bytes[i]}
          # nth_byte_stream2 = CryptBuffer.new(nth_stream)

          nth_byte_stream = input_buf.nth_bytes(keylen,offset: key_byte_pos)
          candidate_map[key_byte_pos] = 0.upto(255).select{|guess| nth_byte_stream.xor_all_with(guess).bytes.all?{|byte| acceptable_char?(byte) } }
          
          jot("found #{candidate_map[key_byte_pos].inspect} bytes for position: #{key_byte_pos}",debug: true)
        end
        candidate_map
      end
      
      private
      
      # Checks if a given byte maps to a reasonable english language character
      def acceptable_char?(byte)
        (byte > 31 && byte < 123) && (byte != 60 && byte !=64)
      end

      
    end
  end
end