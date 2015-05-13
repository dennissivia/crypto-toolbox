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
          h[c] = (h.fetch(c,0) + 1) if c =~ /[A-Za-z ]/
        end
      end
      
      def letter_freq(str)
        counts   = letter_count(str)
        quotient = counts.values.reduce(&:+).to_f
        counts.sort_by{|k,v| v}.reverse.to_h.each_with_object({}){|(k,v),hsh| hsh[k] = (v/quotient) }
      end


    end
  end
end
