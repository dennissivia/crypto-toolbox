require 'crypto-toolbox/crypt_buffer'

module Ciphers
  class InvalidCaesarShift < RuntimeError; end

  class Caesar
    def self.encode(msg,shift)
      ::Ciphers::Caesar.new.encode(msg,shift)
    end
    
    def self.decode(msg,shift)
      ::Ciphers::Caesar.new.decode(msg,shift)
    end

    def encode(message,shift)
      assert_valid_shift!(shift)
      real_shift = convert_shift(shift)
      CryptBuffer.new(message).add(real_shift, mod: 91, offset: 65).str
    end

    def decode(message,shift)
      assert_valid_shift!(shift)
      real_shift = convert_shift(shift)
      # first reduce by 65 to map A to 0 ; then mod-sub with "A"(91)-65; and re-add the 65 to convert back to real ascii A value
      result = CryptBuffer(message).sub(65).mod_sub(real_shift,mod: 91-65).add(65)
      result.str
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
