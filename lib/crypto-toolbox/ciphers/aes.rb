module Ciphers
  class Aes

    def initialize(keysize,mode)
      @cipher = OpenSSL::Cipher::AES.new(keysize,mode)
    end

    def decipher_ecb(input,key)
      @cipher.decrypt
      @cipher.key = key
      (@cipher.update(input) + @cipher.final)
    end
    
    def encipher_ecb(input,key)
    end
  end
end
