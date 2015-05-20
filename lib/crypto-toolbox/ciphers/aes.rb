module Ciphers
  class Aes

    def initialize(keysize,mode)
      @cipher = OpenSSL::Cipher::AES.new(keysize,mode)
    end

    def decipher_ecb(key,input)
      @cipher.decrypt
      @cipher.key = key
      (@cipher.update(input) + @cipher.final)
    end

    def encipher_ecb(key,input)
      @cipher.encrypt
      @cipher.key = key

      encipher_ecb_blockwise(@cipher,CryptBuffer(input).chunks_of(16)) + @cipher.final
    end
    
    def encipher_cbc(key,input,iv: nil)
      blocks = CryptBuffer(input).chunks_of(16)
      iv   ||= blocks.shift.str
      k      = CryptBuffer(key).hex
      xor_input=iv.to_crypt_buffer

      data = blocks.map do |block|
        xored = xor_input ^ block

        _,out = AES.encrypt(xored.str, k, {:format => :plain,:padding => false,:cipher => "AES-128-ECB",:iv => xor_input.str })
        ecb_block = CryptBuffer(out)
        xor_input = ecb_block
        ecb_block.str
      end.join
      (data).to_crypt_buffer
    end
    
    def decipher_cbc(key,input,iv: nil)
      blocks   = CryptBuffer(input).chunks_of(16)
      iv     ||= blocks.shift.str
      k      = CryptBuffer(key).hex
      xor_input=iv.to_crypt_buffer
      
      data = blocks.map do |block|
        out = ::AES.decrypt([xor_input.str,block.str] , k, {:format => :plain,:padding => false,:cipher => "AES-128-ECB",:iv => xor_input.str })
        ecb_block = CryptBuffer(out)
        result    = ecb_block ^ xor_input
        xor_input = block
        result.str
      end.join
      (data).to_crypt_buffer
    end

    private
    def encipher_ecb_blockwise(crypter,blocks)
      blocks.map{|block| encipher_ecb_block(block)  }.join 
    end

    def encipher_ecb_block(crypter,block)
      crypter.update(block.str)
    end
  end
end

