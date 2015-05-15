module Analyzers
  module Utils
    class LetterFrequency
      
      FREQUENCIES={
        ' ' =>  20,  # ??
        'e' =>	12.02,
        't' =>	9.10,
        'a' =>	8.12,
        'o' =>	7.68,
        'i' =>	7.31,
        'n' =>	6.95,
        's' =>	6.28,
        'r' =>	6.02,
        'h' =>	5.92,
        'd' =>	4.32,
        'l' =>	3.98,
        'u' =>	2.88,
        'c' =>	2.71
      }

      
      def letter_count(str)
        str.downcase.each_char.with_object({}) do |c,h|
          h[c] = increment_letter_count(h,c) if countable?(c)
        end
      end
      
      def letter_freq(str)
        counts      = letter_count(str)
        total_chars = counts.values.reduce(&:+)
        Hash[reverse_hash(counts).map{|k,v| [k,calculate_frequency(v,total_chars)] } ]
      end

      
      private

      def reverse_hash(hsh)
        hsh.sort_by{|k,v| -v}
      end
      def calculate_frequency(value,total)
        (value/total.to_f).round(4)
      end

      def increment_letter_count(hsh,char)
        (hsh.fetch(char,0) + 1) 
      end

      def countable?(char)
        char =~ /[A-Za-z ]/
      end
    end
  end
end
