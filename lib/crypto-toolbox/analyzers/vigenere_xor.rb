
=begin
# References:
#
# http://www.ulduzsoft.com/2015/03/breaking-the-vigenere-cipher/
# https://github.com/trekawek/vigenere/blob/master/vig.rb
#
=end
module Analyzers
  class VigenereXor
    def jot(message, debug: false)
      if debug == false || ENV["DEBUG_ANALYSIS"]
        puts message
      end
    end
    def print_delimiter_line
      puts "=====================================================================" 
    end

    # Checks if a given byte maps to a reasonable english language character
    def acceptable_char?(byte)
      (byte > 31 && byte < 123) && (byte != 60 && byte !=64)
    end
    
    def find_pattern(buf)
      bitstring = buf.nth_bits(7).join("")
      
      1.upto([buf.bytes.length,62].min).map do |ksize|
        parts = bitstring.scan(/.{#{ksize}}/)
        if parts.uniq.length == 1
          parts.first
        else
          nil
        end
      end.compact.first
    end
    
    def analyze(input)
      buf = CryptBuffer.from_hex(input)
      result = find_pattern(buf)

      if result.nil?
        $stderr.puts "failed to find keylength by ASCII-8-Bit anlysis"
        exit(1)
      end

      keylen = result.length
      jot "Found recurring key pattern: #{result}"
      jot "Detected key length: #{keylen}"

      candidate_map ={}
      (0..(keylen-1)).each do |key_byte|

        nth_stream = (key_byte).step(buf.bytes.length() -1, keylen).map{|i| buf.bytes[i]}
        smart_buf = CryptBuffer.new(nth_stream)

        candidate_map[key_byte]=[]
        1.upto(255).each do |possible_key_value|
          if smart_buf.xor_all_with(possible_key_value).bytes.all?{|byte| acceptable_char?(byte) }
            jot("YES: " + smart_buf.xor_all_with(possible_key_value).to_s,debug: true)
            candidate_map[key_byte] << possible_key_value
          else
            # the current byte does not create a plain ascii result ( thus skip it )
            #jot  "NO: " + smart_buf.xor_all_with(possible_key_value).to_s
          end
        end
      end

      head,*tail = candidate_map.map{|k,v|v}

      jot "Amount of candidate keys: #{candidate_map.map{|k,v| v.length}.reduce(&:*)}. Starting Permutation (RAM intensive)"  

      combinations = head.product(*tail)
      # make sure all permutations are still according to the bytes per position map
      #x = combinations.select do |arr|
      #  #binding.pry
      #  arr.map.with_index{|e,i| candidate_map[i].include?(e)  }.all?{|e| e ==true}
      #end
      if ENV["SEMI_AUTO_ANALYSIS"] && ENV["DEBUG_ANALYSIS"]
        print_candidate_encryptions(candidate_map,keylen,buf)
      end
      
      results = KeySearch::Filter::AsciiPlain.new(combinations,buf).filter
      report_result(results,buf)
    end

    def report_result(results,buf)
       unless results.empty?
        jot "[Success] Found valid result(s)"
        results.each do |r|
          print_delimiter_line
          jot r.xor(buf).str
          print_delimiter_line
        end
      end
    end
    
    def print_candidate_encryptions(candidate_map,keylen,buf)
      # printout for debugging. (Manual analysis of the characters)
      print "======= Decryption result of first #{keylen} bytes with all candidate keys =======\n" 
      (0..keylen-1).each do|i|
        candidate_map[i].each do |byte|
          print CryptBuffer.new(buf.bytes[i,keylen]).xor(byte).to_s +  " " 
        end
        print "\n"
      end
      print_delimiter_line
    end
    
  end
end

=begin
NOTE: we may at digram and trigram support?
#trigram="the "
#x = CryptBuffer.new(trigram)
=end










