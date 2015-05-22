module Ciphers
  class Aes

    def initialize(key_size: 128)
      @key_size = key_size
      @block_size_bits  = 128
      @block_size_bytes = 16
    end

    # NOTE convert ECB encryption to AES gem or both to openssl
    def decipher_ecb(key,input)
      decipher_ecb_blockwise(CryptBuffer(key),CryptBuffer(input).chunks_of(@block_size_bytes))
    end

    def encipher_ecb(key,input)
      encipher_ecb_blockwise(key,CryptBuffer(input).chunks_of(@block_size_bytes))
    end
    
    def encipher_cbc(key_str,input_str,iv: nil)
      unicipher_cbc(:encipher,key_str,input_str,iv)
    end
    
    def decipher_cbc(key_str,input_str,iv: nil)
      unicipher_cbc(:decipher,key_str,input_str,iv)
    end

    private

    def encipher_ecb_blockwise(key,blocks)
      blocks.map{|block| encipher_ecb_block(key,block)  }.join 
    end

    def encipher_ecb_block(key,block)
      need_padding = block.length < @block_size_bytes
      _,out = AES.encrypt(block.str, key.hex, {:format => :plain,:padding => need_padding,:cipher => "AES-#{@key_size}-ECB"})
      out
    end

    def decipher_ecb_blockwise(key,blocks)
      blocks.map{|block| decipher_ecb_block(key,block)  }.join 
    end

    def decipher_ecb_block(key,block)
      need_padding = block.length < @block_size_bytes
      AES.decrypt(["",block.str], key.hex, {:format => :plain,:padding => need_padding,:cipher => "AES-#{@key_size}-ECB"})
    end
    
    # this method is used for encipher and decipher since most of the code is identical
    # only the value of the previous block and the internal ecb method differs
    def unicipher_cbc(direction,key_str,input_str,iv)
      method="#{direction.to_s}_cbc_block"
      blocks = CryptBuffer(input_str).chunks_of(@block_size_bytes)
      iv   ||= blocks.shift.str
      key    = CryptBuffer(key_str).hex
      
      prev_block=iv.to_crypt_buffer

      blocks.map do |block|
        ctext_block = send(method,key,block,prev_block) #encipher_cbc_block(key,block,prev_block)
        if direction == :encipher
          prev_block  = ctext_block
        else
          prev_block  = block
        end

        ctext_block.str
      end.join.to_crypt_buffer
    end
    
    def encipher_cbc_block(key,block,prev_block)
      xored =  block ^ prev_block
      need_padding = block.length != @block_size_bytes
      
      _,out = AES.encrypt(xored.str, key, {:format => :plain,:padding => need_padding,:cipher => "AES-#{@key_size}-ECB",:iv => prev_block.str })
      ecb_block = CryptBuffer(out)
    end
    def decipher_cbc_block(key,block,prev_block)
      need_padding = block.length != @block_size_bytes
      
      out = ::AES.decrypt([prev_block.str,block.str] , key, {:format => :plain,:padding => need_padding,:cipher => "AES-#{@key_size}-ECB",:iv => prev_block.str })
      ecb_block = CryptBuffer(out)
      ecb_block ^ prev_block
    end
    
  end
end

