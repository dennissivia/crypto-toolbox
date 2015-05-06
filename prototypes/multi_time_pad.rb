require 'crypto-toolbox'
require 'pry'
require 'pp'

class CryptoAnalyzer
  class MultiTimePad
    def initialize
      @spellcheck =  ::Analyzers::Utils::SpellChecker.new("en_GB")
    end
    def run(cipher_texts)
      keylen=CryptBuffer.from_hex(cipher_texts.first).length
      puts "keylen : #{keylen}"

# all cipher text combinatinos without repitition
# NOTE combination(2) is much more precise than creating the product and reducing it afterwards
#combinations = cipher_texts.product(cipher_texts).map(&:sort).uniq.select{|l,r| l != r }
      combinations = cipher_texts.combination(2)
      xored_ctexts = combinations.map{|l,r| CryptBuffer.from_hex(l).xor(CryptBuffer.from_hex(r)) }
      samples      = xored_ctexts.map{|m| m.xor_space.chars.map{|char| char.match(/[a-zA-Z]/).nil? ? nil : char } }

      
      while
        sleep 0.2

        ref_score = guess(xored_ctexts,"").first
          
        ngrams = ["The","the","They","When","I am"]


        spell  = ::Analyzers::Utils::SpellChecker.new("en_GB")
=begin
NOTE score based analysis ( total or max ) does not work.
=end
         
        input = "When"
        score,words,data = guess(xored_ctexts,input)
        search_in(data)
        
        binding.pry        

      end
      result_candidates = words.map{|v| v.join(" ") }.select{|c| c.length == keylen }

      unless result_candidates.empty?
        result_candidates.unshift(guess)
      end
      result_candidates
    end

    def search_in(strings)
      strings.each do |string|
         string.chars.each_with_index do |char,pos|  
           sub = string[0,pos]    
           puts "<#{sub}> in '#{string}'" if sub.length > 1 && @spellcheck.human_phrase?(sub)    
         end
      end
    end


    def guess(ctexts,input)
      data   = test_plain(ctexts,input)
      score = spell_score_for(data)
      words = spell_words_for(data)
      [score,words,data]
    end
    def ascii_whitelist
      (32..127).to_a - ascii_blacklist
    end
    def ascii_blacklist
      [40,41,42,43,47,60,61,62,91,92,93,94,95,96,35,59] # # ; 
    end
    def ascii_lingual?(byte)
    
      ascii_whitelist.include?(byte)
    end
    
    def test_plain(all,plain)
      all.map{|combi| combi.xor(plain).bytes.map{|byte| ascii_lingual?(byte) ? byte : " ".bytes.first } }.map{|e| CryptBuffer(e).str}
    end
    
    def spell_score_for(texts)
      texts.map{|e| @spellcheck.known_words(e).count}.reduce(&:+)
    end
    
    def spell_words_for(texts)
      texts.map{|e| @spellcheck.known_words(e)}.map{|arr| arr.select{|e| e =~ /[a-zA-Z]/}}
    end


  end
end


cipher_texts = %w(
BB3A65F6F0034FA957F6A767699CE7FABA855AFB4F2B520AEAD612944A801E
BA7F24F2A35357A05CB8A16762C5A6AAAC924AE6447F0608A3D11388569A1E
A67261BBB30651BA5CF6BA297ED0E7B4E9894AA95E300247F0C0028F409A1E
A57261F5F0004BA74CF4AA2979D9A6B7AC854DA95E305203EC8515954C9D0F
BB3A70F3B91D48E84DF0AB702ECFEEB5BC8C5DA94C301E0BECD241954C831E
A6726DE8F01A50E849EDBC6C7C9CF2B2A88E19FD423E0647ECCB04DD4C9D1E
BC7570BBBF1D46E85AF9AA6C7A9CEFA9E9825CFD5E3A0047F7CD009305A71E
)

if $0 == __FILE__
  result = CryptoAnalyzer::MultiTimePad.new.run(cipher_texts)
  puts "found solution with a length that matches the keylen!!!"
  puts result.join("\n")
end
