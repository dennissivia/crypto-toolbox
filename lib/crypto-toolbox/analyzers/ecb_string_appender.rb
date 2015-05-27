module Analyzers

  # Public: This analyzer attacks oracles that append any unknown string to
  # its input messages and decrypts the appended string.
  # In practice Email autoresponders sometimes append a data to a given input.
  # Thus this analyzer can break any ecb encryption that works this way
  #
  # it is also capable of detecting prefixes created by the oracle and pad them
  # to correctly analyze the target message
  #

  class EcbStringAppender

    class DuplicateDecryptionDictionaryEntry < RuntimeError; end
    
    DUMMY = "A".freeze
    PREFIX_PAD_DUMMY="P".freeze
    MAX_KNOWN_BLOCK_LENGTH = 64 # 512 Bit block length
    attr_reader :oracle

    include ::Utils::Reporting::Console
    
    def initialize(oracle)
      @oracle    = oracle
      detect_block_size!
      raise "None-ECB oracle" unless ::Utils::EcbDetector.new.is_ecb?(@oracle.encipher(DUMMY * (block_size * 6)))
    end

    
    def analyze
      analyze_oracle!
      
      suffix_block_ids.with_object("") do |block_id, hits|
        each_block_position do |pos|
          # stop as soon as we have all the bytes that are appended ( without and ciphermode padding )
          break if hits.length >= real_suffix_length
          hits << attempt_match(hits, block_id, pos)
        end
      end
    end
    
    private
    
    # first we pre calculate all the data we can deduce from the oracle's behaviour
    def analyze_oracle!
      detect_prefix
      detect_suffix
    end

    
    # left align our attack vector
    # this means full any left randomness to a full block
    # example
    #
    # <random[0-16]> || <input-blocks[any]> || <target-data[any]>
    def detect_prefix
      # 0 * "X" == "" for no prefix
      @prefix_pad    = PREFIX_PAD_DUMMY * calculate_prefix_length
      @prefix_blocks = @prefix_pad.empty? ? 0 : 1
      @prefix_bytes  = @prefix_blocks * block_size
      jot("detected oracle prefix with length: #{@prefix_pad.length} (#{@prefix_blocks} blocks)",debug: true) unless @prefix_pad.empty?      
    end

    def detect_block_size!
      @block_size = calculate_block_size
    end
    
    def detect_suffix
      @aligned_suffix_length ||= calculate_aligned_suffix_length
      @suffix_blocks         ||= aligned_suffix_length / block_size
      @real_suffix_length    ||= calculate_real_suffix_length(oracle,block_size,aligned_suffix_length) 
    end

    def block_size
      @block_size 
    end

    def aligned_suffix_length
      @aligned_suffix_length 
    end
    
    def suffix_blocks
      @suffix_blocks
    end
    
    def real_suffix_length
      @real_suffix_length 
    end
    
    def each_block_position(&block)
      1.upto(block_size,&block)
    end


    
    def attempt_match(hits, block_id, pos)
      msg = @prefix_pad + (DUMMY * (block_size - pos))
      relevant_bytes = block_size * (block_id.succ)

      # build a dictionary for the current dummy + all hits
      # resulting in entries with block_size -1 length
      dict   = assemble_dict(oracle,msg + hits,relevant_bytes)
      result = @oracle.encipher(msg)[@prefix_bytes,relevant_bytes] # skip all prefix blocks

      dict[result].tap do |match|
        jot(match,debug: true,raw: true) unless match.nil?
        if match.nil?
          raise "Could not find dictonary entry for block #{block_id}, pos: #{pos}"
        end
      end
    end
    
    
    # calculate the block size by detecting the growth
    # of the resulting ciphertext by sending messages
    # which length increases by one until a change occurs
    def calculate_block_size
      char_amount = 1
      base_length = @oracle.encipher(DUMMY * char_amount).length
      result = nil
      (1..MAX_KNOWN_BLOCK_LENGTH).each do |length|
        new_length   = @oracle.encipher(DUMMY * char_amount).length
        if new_length > base_length
          result = new_length - base_length
          break
        end
        char_amount += 1
      end
      result
    end

    # in case of a prefix some bytes of your 2 duplicate / redundant chars
    # will be part of the first block, thus need to add enough extra chars
    # to fill the first block containinig the random + unknown prefix with
    # dummy chars to align it to the block length. 
    def calculate_prefix_length
      duplications = 2

      (0..(block_size() -1)).each do |pad_length|
        # construct a message like this:
        # 1 <unknown-prefix>|| prefix_pad * DUMMY
        # 2 DUMMY * (block_size)
        # 3 DUMMY * (block_size)
        # 4 - (n-1) Target Message
        # 5: target_end + pkcs#7 padding
        malicious_msg = (PREFIX_PAD_DUMMY * pad_length) + (DUMMY * (block_size * duplications)) 
        ciphertext = @oracle.encipher(malicious_msg)
        
        return pad_length if block_is_left_aligned?(ciphertext,duplications)
      end
    end

    # Check whether we need to pad any oracle prefix.
    # For example: if the oracle prepends 7 bytes to all messages
    # we have to add block_size - 7 bytes to "left-align" our messages
    def block_is_left_aligned?(ciphertext,redundant_test_blocks)
      total_blocks = ciphertext.length / block_size
      uniq_blocks  = CryptBuffer(ciphertext).chunks_of(block_size).map(&:bytes).uniq.length

      (total_blocks - uniq_blocks ) == (redundant_test_blocks -1) 
    end
    

    def suffix_block_ids
      0.upto(suffix_blocks.pred)
    end
    


    # prefix_pad can be empty || then prefix_blocks is 0
    # this results in the simple case of no prefix and no substraction
    def calculate_aligned_suffix_length
      # substract the prefix block if given
      @oracle.encipher(@prefix_pad + "").length() - (@prefix_blocks * block_size)
    end
    
    
    def calculate_real_suffix_length(oracle,block_size,minimum_length)
      # map has a smell, that is does not abort and thus create unnecessary
      # requests... while, count++; break; smells even worse
      (0..block_size).each do |i|
        total_length = oracle.encipher(@prefix_pad + (DUMMY * i) ).length
        result       = total_length - (@prefix_blocks * block_size )
        if result > minimum_length
          return minimum_length - (i-1)
        end
      end
    end
    
    def assemble_dict(oracle,prefix,relevant_bytes)
      # we could also iterate over all bytes, but as long as we decrypt plain english we can
      # reduce the number of iterations by just checking printable chars
      #   (0..255).map(&:chr).each_with_object({}) do |char,hsh|

      # cache for performance
      @chars ||= Analyzers::Utils::AsciiLanguageDetector.new.ascii_lingual_chars.map(&:chr)

      @chars.each_with_object({}) do |char,hsh|
        msg    = prefix + char
        ciphertext = oracle.encipher(msg)[@prefix_bytes,relevant_bytes].freeze
        raise DuplicateDecryptionDictionaryEntry,"ciphertext #{ciphertext} is alredy in the dictionary" if hsh.has_key?(ciphertext)
        hsh[ciphertext] = char  # skip prefix blocks during [] access
      end
    end
      
  end
end
