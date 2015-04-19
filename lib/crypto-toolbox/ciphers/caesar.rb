
module Ciphers
  class InvalidCaesarShift < RuntimeError; end

  class Caesar
    def self.encipher(msg,shift)
      ::Ciphers::Caesar.new.encipher(msg,shift)
    end
    
    def self.decipher(msg,shift)
      ::Ciphers::Caesar.new.decipher(msg,shift)
    end
=begin
Within encipher and decipher we use a regexp comparision.
Array lookups are must slower and byte comparision is a little faster,
but much more complicated


Alphabet letter lookup algorithm comparision:

Comparison: (see benchmarks/string_comparision.rb)
string.bytes.first == A :  3289762.7 i/s
string =~ [A-Za-Z]      :  2010285.8 i/s - 1.64x slower
Letter Array include?(A):    76997.0 i/s - 42.73x slower

=end
    def encipher(message,shift)
      assert_valid_shift!(shift)
      real_shift = convert_shift(shift)
      
      message.split("").map do|char|
        mod    = (char =~ /[a-z]/) ? 123 : 91
        offset = (char =~ /[a-z]/) ? 97  : 65
        
        (char =~ /[^a-zA-Z]/) ? char : CryptBuffer.new(char).add(real_shift, mod: mod, offset: offset).str
      end.join
    end

    def decipher(message,shift)
      assert_valid_shift!(shift)
      real_shift = convert_shift(shift)
      
      message.split("").map do |char|
        mod    = (char =~ /[a-z]/) ? 123 : 91
        offset = (char =~ /[a-z]/) ? 97  : 65
        
        # first reduce by 65 to map A to 0 ; then mod-sub with "A"(91)-65; and re-add the 65 to convert back to real ascii A value
        (char =~ /[^a-zA-Z]/) ? char :  CryptBuffer(char).sub(offset).mod_sub(real_shift,mod: mod-offset).add(offset).str
      end.join
    end
    private

    def assert_valid_shift!(shift)
      raise InvalidCaesarShift,shift unless shift =~ /[A-Z]{1}/
    end

    def convert_shift(shift)
      ("A".."Z").to_a.each.with_index.with_object({}){|(val,index),hsh| hsh[val] = index }[shift]
    end
  end
  
end
