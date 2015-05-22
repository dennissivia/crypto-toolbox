module Analyzers
  class EcbStringAppender
    attr_reader :oracle
    def initialize(oracle)
      @oracle = oracle
    end

    def analyze
      dummy      = "A"
      blocksize  = oracle.encipher("\0").length()
      ciphertext = oracle.encipher(dummy * (blocksize * 2))
      detector   = ::Utils::EcbDetector.new
        
      aligned_suffix_length = oracle.encipher("",append: true).length
      real_suffix_length    = calculate_real_suffix_length(oracle,blocksize,aligned_suffix_length) #aligned_suffix_len -1 # substract the test byte \0
      suffix_blocks         = aligned_suffix_length / blocksize
      
      raise "None-ECB oracle" unless detector.is_ecb?(ciphertext)

      # keep the length of the msg construction (n*dummy + last )
      hits = []
      (0..(suffix_blocks-1)).each do |block_id|
        (1..blocksize).each do |pos|
          # stop as soon as we have all the bytes that are appended ( without and ciphermode padding )
          break if hits.length >= real_suffix_length
          
          msg    = (dummy * (blocksize - pos))
          # build a dictionary for the current dummy + all hits
          # resulting in entries with blocksize -1 length
          dict   = assemble_dict(oracle,msg + hits.join)
          result = oracle.encipher(msg,append: true)[0,blocksize*(block_id+1)]
          match  = dict[result]
          raise "Could not find dictonary entriy for block #{block_id}, pos: #{pos}" if match.nil?
          hits << match
        end
      end
      hits.join
    end

    
    private
    def calculate_real_suffix_length(oracle,blocksize,minimum_length)
      dummy = "\0"
      # map has a smell, that is does not abort and thus create unnecessary
      # requests... while, count++; break; smells even worse
      (0..blocksize).each do |i|
        result = oracle.encipher(dummy * i,append: true)
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
