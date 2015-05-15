require 'ffi/hunspell'
#require 'ffi/aspell'

module Analyzers
  module Utils
    class SpellChecker
      
      def initialize(dict_lang="en_US")
        @dict = FFI::Hunspell.dict(dict_lang)
        # @dict2 = FFI::Aspell::Speller.new(dict_lang)
      end
=begin
NOTE: About spelling error rates and language detection:

missing punctuation support may lead to > 2% errors on valid texts, thus we use a high value .
invalid decryptions tend to have spell error rates > 70
Some statistics about it:
> summary(invalids)
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max. 
 0.6000  1.0000  1.0000  0.9878  1.0000  1.0000 
> summary(cut(invalids,10))
 (0.6,0.64] (0.64,0.68] (0.68,0.72] (0.72,0.76]  (0.76,0.8]  (0.8,0.84] 
          8          13           9         534        1319        2809 
(0.84,0.88] (0.88,0.92] (0.92,0.96]    (0.96,1] 
      10581       46598      198477     1440651 

NOTE: There is ony caveat: Short messages with < 5 words may have 33 or 50% error rates
if numbers or single char words are taken into account
=end
      def known_words(str)
        words = str.split(" ").select{|w| check?(w) }
      end

      def human_word?(str)
        check?(str)
      end
      
      def human_phrase?(string)
        string.split(" ").all?{|part| human_word?(part)}
      end

      def suggest(str)
        @dict.suggest(str)
      end

      # Check whether a given string seems to be part of a human language using the given dictionary
      #
      # NOTE:
      # Using shell instead of hunspell ffi causes lots of escaping errors, even with shellwords.escape
      # errors = Float(`echo '#{Shellwords.escape(str)}' |hunspell -l |wc -l `.split.first)
      def human_language?(str)
        #NOTE should be reject 1char numbers or all 1 char symbols
        words       = str.split(" ").reject{|w| (w.length < 2 || w =~ /^[0-9]+$/) }
        word_amount = words.length
        errors      = words.map{|e| check?(e) }.count{|e| e == false}
        
        error_rate = errors.to_f/word_amount

        report_error_rate(str,error_rate) if ENV["DEBUG_ANALYSIS"]

        error_rate_sufficient?(error_rate)
      end
      
      private

      def report_error_rate(str,error_rate)
        if ENV["DEBUG_ANALYSIS"]
          $stderr.puts "=================================================="
          $stderr.puts "str: #{str} has error rate: #{error_rate.round(4)}"
          $stderr.puts "=================================================="
        end
      end

      # note:
      # Aspell is much faster but requires expensive and slow removal of all punctuation marks
      # which makes it slower than hunspell.
      # Thus we stick with hunspell for correctness and speed.
      def check?(input)
        @dict.check?(input) rescue false
        # @dict2.correct?(input.gsub(/[^a-zA-Z]/,""))
      end
      
      def error_rate_sufficient?(rate)
        rate < 0.20
      end
    end
  end
end
