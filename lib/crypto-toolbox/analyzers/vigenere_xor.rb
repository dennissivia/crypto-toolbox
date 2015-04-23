require 'crypto-toolbox/analyzers/utils/key_candidate_map.rb'

=begin
# References:
#
# http://www.ulduzsoft.com/2015/03/breaking-the-vigenere-cipher/
# https://github.com/trekawek/vigenere/blob/master/vig.rb
#
=end
module Analyzers
  class VigenereXor
    # This crypto analyzers takes a hex encoded ciphertext as input string
    # and tries to find the plaintext by doing the following crypto analysis:
    #
    # 1) Search for a recurring pattern of the 8th bit of the ciphertext
    # since ascii plaintext chars to have this bit set, the pattern will
    # imply the key length
    #
    # 2) Create a map of all possible bytes for every position of the key
    # The amount of candidates can be reduced by only allowing bytes that
    # lead to a ascii english char
    #
    # 3) create the product of all possible combinations
    # This only works for short key lengths due to the exponential growth
    #
    # 4) Do an English language Analysis of the possible result by using
    # the error rate of the candidate plaintext using hunspell
    
    include ::Utils::Reporting::Console
    
    def find_pattern(buf)
      bitstring = buf.nth_bits(7).join("")
      
      1.upto(buf.bytes.length).map do |ksize|
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
## === Should this be extracted into a dedicated class ?
      # Example: "100100" || nil
      key_pattern = find_pattern(buf)

      assert_key_pattern!(key_pattern)
      
      report_pattern_info(key_pattern)

##====
      
      candidate_map = Analyzers::Utils::KeyCandidateMap.create(buf,key_pattern.length)
      jot "Amount of candidate keys: #{candidate_map.map{|k,v| v.length}.reduce(&:*)}. Starting Permutation (RAM intensive)"
      
      # split the candidate map into head and*tail to create the prduct of all combinations
      head,*tail = candidate_map.map{|k,v|v}
      combinations = head.product(*tail)

      if ENV["DEBUG_ANALYSIS"]
        ensure_consistent_result!(combinations,candidate_map)
        print_candidate_decryptions(candidate_map,key_pattern.length,buf)
      end
      
      results = Analyzers::Utils::KeyFilter::AsciiPlain.new(combinations,buf).filter
      report_result(results,buf)
    end
    private
    def assert_key_pattern!(key_pattern)
      if key_pattern.nil?
        $stderr.puts "failed to find keylength by ASCII-8-Bit anlysis"
        exit(1)
      end
    end

    def ensure_consistent_result!(combinations,condidate_map)
      # NOTE Consistency check ( enable if you dont trust the generation anymore )
      # make sure all permutations are still according to the bytes per position map
      combinations.select do |arr|
        raise "Inconsistent key candidate combinations" unless arr.map.with_index{|e,i| candidate_map[i].include?(e)  }.all?{|e| e ==true}
      end      
    end

    def report_pattern_info(key_pattern)
      jot "Found recurring key pattern: #{key_pattern}"
      jot "Detected key length: #{key_pattern.length}"
    end
      

    def report_result(results,buf)
       unless results.empty?
        jot "[Success] Found valid result(s):"
        results.each do |r|
          jot r.xor(buf).str
        end
      end
    end
    
    def print_candidate_decryptions(candidate_map,keylen,buf)
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










