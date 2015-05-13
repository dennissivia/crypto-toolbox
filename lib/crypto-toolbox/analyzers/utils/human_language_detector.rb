module Analyzers
  module Utils
    # NOTE the implementation decisions are based on the result of
    # benchmarks/language_detector.rb
    class HumanLanguageDetector
      def initialize
        @spell_checker = ::Analyzers::Utils::SpellChecker.new
        @ascii_checker = ::Analyzers::Utils::AsciiLanguageDetector.new
      end

      # NOTE: we dont use the human_language? method
      # to be faster at processing and more idiomatic
      def human_language_entries(buffers,spellcheck: true )
        filtered = buffers.select{|b| ascii_valid?(b) }
        if spellcheck
          buffers.select{|b| spell_valid?(b) }
        else
          filtered
        end
      end
      
      def human_language?(buffer)
        ascii_valid?(buffer) && spell_valid?(buffer)
      end
      
      private

      def ascii_valid?(buf)
        @ascii_checker.ascii_lingual?(buf)
      end
      
      def spell_valid?(buf)
        @spell_checker.human_language?(buf.str)
      end
    end
  end
end
