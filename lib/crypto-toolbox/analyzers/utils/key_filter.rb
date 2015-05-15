require 'crypto-toolbox/analyzers/utils/spell_checker.rb'

module Analyzers
  module Utils
    module KeyFilter
      class AsciiPlain

        def initialize(keys,ciphertext)
          @keys = keys
          @c = @ciphertext = ciphertext
          @keylen = keys.first.length
          @detector = Analyzers::Utils::HumanLanguageDetector.new
          @spell_checker = Analyzers::Utils::SpellChecker.new("en_US")
        end

        def filter
          # how often is the key repeated 
          reps = @c.bytes.length / @keylen
          result =[]

          

          
          # should we fork here ?
          @keys.each_with_index do |key,i| #  i is used as a simple counter only !
            test = CryptBuffer.new(@c.bytes[0,@keylen]).xor(key).str
            repkey = CryptBuffer.new((key*reps) + key[0,(@c.bytes.length % reps).to_i])
            str  = @c.xor(repkey).to_s
            
            # NOTE: we dont need the ASCII check provided by the human language detector
            # since the key selection is usually based on ascii value checks
            if @spell_checker.human_language?(str)
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
end
