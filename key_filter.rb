load 'crypt_buffer.rb'
load 'spell_checker.rb'
require 'pry'

module KeySearch
  module Filter
    class AsciiPlain
      def initialize(keys,ciphertext,dict_lang="en_GB")
        @keys = keys
        @c = @ciphertext = ciphertext
        @keylen = keys.first.length
        @dict = FFI::Hunspell.dict(dict_lang)
      end


      def filter
        # how often is the key repeated 
        reps = @c.bytes.length / @keylen
        result =[]
        spell_checker = SpellChecker.new("en_GB")
        
        @keys.each_with_index do |key,i| #  i is used as a simple counter only !
          test = CryptBuffer.new(@c.bytes[0,@keylen]).xor(key).str
          repkey = CryptBuffer.new((key*reps) + key[0,(@c.bytes.length % reps).to_i])
          str    = @c.xor(repkey).to_s

          if spell_checker.check(str)
            result << repkey
            break
          else
            if (i % 50000).zero?
              puts "[Progress] #{i}/#{@keys.length} (#{(i.to_f/@keys.length*100).round(4)}%)"
            end
          end
        end
        return result
      end
      
    end
  end
end
