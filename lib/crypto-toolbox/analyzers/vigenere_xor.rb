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

    class HammingDistanceKeyLengthFinder
      def keylen_for(buffer)
        offset = 2
        distances = ((0+offset)..64).map do |keysize|
          # take the first 4 blocks of keysize length, generate all combinations (6),
          # map than to normalized hamming distance and take mean
          buffer.chunks_of(keysize)[0,4].combination(2).map{|a,b| a.hdist(b,normalize: true)}.reduce(&:+) / 6.0
        end
        # get the min distance, find its index, convert the keylen
        distances.min(4).map{|m| distances.index(m)}.map{|i| i + offset }.uniq
      end
    end
    
    class EightBitPatternFinder
      include ::Utils::Reporting::Console
      def keylen_for(buf)
        # Example: "100100" || nil
        key_pattern = find_pattern(buf)
        
        assert_key_pattern!(key_pattern)
        
        report_pattern_info(key_pattern)

        [key_pattern.length]
      end
      
      private
      
      def assert_key_pattern!(key_pattern)
        if key_pattern.nil?
          $stderr.puts "failed to find keylength by ASCII-8-Bit anlysis"
          exit(1)
        end
      end

      def report_pattern_info(key_pattern)
        jot "Found recurring key pattern: #{key_pattern}"
        jot "Detected key length: #{key_pattern.length}"
      end
      
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
    end

    class StaticKeylength
      def initialize(keylength)
        @keylength = keylength
      end
      def keylen_for(dummy)
        [@keylength]
      end
    end


    
    def analyze(input, keylength_strategy=EightBitPatternFinder.new)
      buf = CryptBuffer.from_hex(input)

      keylength_strategy.keylen_for(buf).map do |keylen|
        analyse_single(buf,keylen)
      end.flatten
    end


    
    def analyse_single(buf,key_length)
      candidate_map = Analyzers::Utils::KeyCandidateMap.create(buf,key_length)

     
      candidate_amount = candidate_map.map{|k,v| v.length}.reduce(&:*)
      if candidate_amount.zero?
        jot("no combinations for keylen #{key_length} (at least one byte has no candidates)",debug: true)
        return []
      end
      jot "Amount of candidate keys: #{candidate_map.map{|k,v| v.length}.reduce(&:*)}. Starting Permutation (RAM intensive)",debug: true

      
      # split the candidate map into head and*tail to create the prduct of all combinations
      head,*tail = candidate_map.map{|k,v|v}
      begin
        combinations = head.product(*tail) 
        # we simply skip too big products
      rescue RangeError => ex
        jot "keylen: #{key_length}: #{ex}"
        return []
      end


      
      if ENV["DEBUG_ANALYSIS"]
        ensure_consistent_result!(combinations,candidate_map)
        print_candidate_decryptions(candidate_map,key_length,buf)
      end

      
      keys = Analyzers::Utils::KeyFilter::AsciiPlain.new(combinations,buf).filter.reject(&:empty?)

      # return the result, not the key
      keys.map do|key|
        key.xor(buf)
      end
    end
    private

    def ensure_consistent_result!(combinations,candidate_map)
      # NOTE Consistency check ( enable if you dont trust the generation anymore )
      # make sure all permutations are still according to the bytes per position map
      combinations.select do |arr|
        raise "Inconsistent key candidate combinations" unless arr.map.with_index{|e,i| candidate_map[i].include?(e)  }.all?{|e| e ==true}
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










