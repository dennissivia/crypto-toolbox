
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
      buf = CryptBuffer.new(input)
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

if $0 == __FILE__

  input = ARGV[0] || "0xF96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794"
  analyzer = Analyzers::VigenereXor.new.analyze(input)
end










