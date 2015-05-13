module Analyzers
  module Utils
    class AsciiLanguageDetector
      ASCII_BASE_RANGE=(32..127).freeze
      ASCII_BLACKLIST = [40,41,42,43,47,60,61,62,91,92,93,94,95,96,35,59].freeze 
      ASCII_WHITELIST = [10]
      ASCII_CHARACTERS = ( ASCII_BASE_RANGE.to_a + ASCII_WHITELIST - ASCII_BLACKLIST ).to_ary.freeze # 10 == \n is now allowed!
=begin
NOTE: This is the output of the benchmark script contained in this gem
      see: benchmarks/language_detection.rb
It compares many ways of filtering bytes to check if only "plain" language
characters are contained. Result:

Comparison:
   ascii_range_check:                 1773.5 i/s                <- use range.cover? and then blacklist.include
 ascii_lingual_byte?:                 1494.8 i/s - 1.19x slower <- now uses range.cover? internally
ascii_lingual_bytes?:                 1459.2 i/s - 1.22x slower <- see prev. but get the entire byte array
      ascii_lingual?:                 1420.1 i/s - 1.25x slower <- see prev. but works on crypt buffers
ascii_lingual_and_human_language:     1413.6 i/s - 1.25x slower  <- use human_languge?, but apply 0 < byte < 127 first
   ascii_shift_check:                  634.4 i/s - 2.80x slower  <- uses & (1 << 5).zero? but has to do slow additional checks
ascii_whitelist.bsearch?:              483.8 i/s - 3.50x slower  <- whitelist lookup using bsearch
hunspell.human_language?:              212.3 i/s - 8.35x slower  <- use human_languge?
ascii_whitelist.include?:               90.2 i/s - 19.67x slower <- use (whitelist - blacklist).include?
hunspell_human_language_without_dict:    0.2 i/s - 10013.62x slower <- instanciating the dict seems to be very very slow...

NOTE:
  Normally the shift solution would be the fastes, but we have to convert back and forth,
  thus the range.cover? check still seems to be the best soution. It is also more readable

  (We need the chr.downcase.ord conversion to support upper case letters)
  byte < 127 && !(byte.chr.downcase.ord & (1 << 5)).zero?
=end
      def ascii_lingual_byte?(byte)
        # check how fast bsearch is, if range.cover is no longer needed we can nicely add 10 to the array
        (ascii_base_range.cover?(byte) && !ascii_blacklist.include?(byte)) || ( ascii_whitelist.bsearch{|i| i == byte} )
      end
      
      def ascii_lingual_bytes?(bytes)
        bytes.all?{|b| ascii_lingual_byte?(b) }
      end

      def ascii_lingual_chars
        ASCII_CHARACTERS
      end
      
      def ascii_lingual?(buf)
        ascii_lingual_bytes?(buf.bytes)
      end

      def ascii_lingual_bytes
        ascii_whitelist.to_ary
      end

      private
     
      # building up the range is too slow, thus we cache
      def ascii_base_range
        ASCII_BASE_RANGE
      end
      
      def ascii_whitelist
        ASCII_WHITELIST
      end

      def ascii_blacklist
        ASCII_BLACKLIST
      end

    end
  end
end
      
