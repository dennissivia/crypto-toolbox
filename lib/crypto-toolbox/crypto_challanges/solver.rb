
module CryptoChallanges
  class Solver
    def solve1(input)
      #CryptoChallanges::Set1::Challange1::Solver.run(input)
      CryptBuffer.from_hex(input).base64
    end
    def solve2(c1,c2)
      (CryptBuffer.from_hex(c1) ^ CryptBuffer.from_hex(c2)).hex.downcase
    end
    
    def solve3(input)
      candidates = (1..256).map{ |guess| CryptBuffer.from_hex(input).xor_all_with(guess) }
      detector = Analyzers::Utils::HumanLanguageDetector.new
      
      detector.human_language_entries(candidates).first.to_s
    end

    # challange:
    # One of the 60-character strings in this file has been encrypted by single-character XOR.
    def solve4(hexstrings)
      detector = Analyzers::Utils::HumanLanguageDetector.new
      result = hexstrings.map{|h| CryptBuffer.from_hex(h)}.map.with_index do |c,i|
        candidates = (1..256).map{ |guess| c.xor_all_with(guess) }
        matches = detector.human_language_entries(candidates)

        matches.empty? ? nil : matches
      end
      result.flatten.compact.map(&:str).first
    end
    
    def solve5(input,key)
      CryptBuffer(input).xor(key,expand_input: true).hex
    end

    def solve6(input)
      buffer = CryptBuffer.from_base64(input)
      Analyzers::VigenereXor.new.analyze(buffer.hex,Analyzers::VigenereXor::HammingDistanceKeyLengthFinder.new)
    end

    def solve7(input,key)
      data = CryptBuffer.from_base64(input).str
      Ciphers::Aes.new(128,:ECB).decipher_ecb(data,key)
    end

    def solve8(ciphers)
      binding.pry
    end
  end
end
