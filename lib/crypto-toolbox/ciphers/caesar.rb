
module Ciphers
  class InvalidCaesarShift < RuntimeError; end

  class Caesar
    def self.encipher(msg,shift)
      ::Ciphers::Caesar.new.encipher(msg,shift)
    end
    
    def self.decipher(msg,shift)
      ::Ciphers::Caesar.new.decipher(msg,shift)
    end

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
      ("A".."Z").to_a.each_with_index.inject({}){|memo,(val,index)| memo[val] = index; memo }[shift]
    end
  end
  
end
