module Analyzers

  # Public: This analyzer attacks oracles that append any unknown string to
  # its input messages and decrypts the appended string.
  # In practice Email autoresponders sometimes append a data to a given input.
  # Thus this analyzer can break any ecb encryption that works this way
  #
  # Examples
  #
  
  class EcbStringAppender
    DUMMY = "A".freeze
    attr_reader :oracle
    
    def initialize(oracle)
      @oracle    = oracle
      raise "None-ECB oracle" unless ::Utils::EcbDetector.new.is_ecb?(@oracle.encipher(DUMMY * (block_size * 2)))
    end

    def analyze
      suffix_block_ids.with_object("") do |block_id, hits|
        each_block_position do |pos|
          # stop as soon as we have all the bytes that are appended ( without and ciphermode padding )
          break if hits.length >= real_suffix_length
          hits << attempt_match(hits, block_id, pos)
        end
      end
    end
    
    private
    
    def attempt_match(hits, block_id, pos)
      msg = (DUMMY * (block_size - pos))

      # build a dictionary for the current dummy + all hits
      # resulting in entries with block_size -1 length
      dict   = assemble_dict(oracle,msg + hits)
      result = @oracle.encipher(msg,append: true)[0,block_size * (block_id.succ)]

      dict[result].tap do |match|
        if match.nil?
          raise "Could not find dictonary entriy for block #{block_id}, pos: #{pos}"
        end
      end
    end
    def each_block_position(&block)
      1.upto(block_size,&block)
    end

    def block_size
      @block_size ||= @oracle.encipher("\0").size
    end
    def suffix_blocks
      @suffix_blocks ||= aligned_suffix_length / block_size
    end

    def suffix_block_ids
      0.upto(suffix_blocks.pred)
    end
    
    def aligned_suffix_length
      @aligned_suffix_length ||= @oracle.encipher("", append: true).length
    end
    
    def real_suffix_length
      @real_suffix_length ||= calculate_real_suffix_length(oracle,block_size,aligned_suffix_length) 
    end
    
    def calculate_real_suffix_length(oracle,block_size,minimum_length)
      # map has a smell, that is does not abort and thus create unnecessary
      # requests... while, count++; break; smells even worse
      (0..block_size).each do |i|
        result = oracle.encipher(DUMMY * i,append: true)
        if result.length > minimum_length
          return minimum_length - (i-1)
        end
      end
    end
    
    def assemble_dict(oracle,prefix)
      Analyzers::Utils::AsciiLanguageDetector.new.ascii_lingual_chars.map(&:chr).each_with_object({}) do |char,hsh|
        #(0..255).map(&:chr).each_with_object({}) do |char,hsh|
        msg    = prefix + char
        hsh[oracle.encipher(msg).freeze] = char
      end
    end
      
  end
end
