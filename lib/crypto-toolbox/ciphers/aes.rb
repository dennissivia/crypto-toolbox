# coding: utf-8
module Ciphers
  class Aes

    def initialize(key_size: 128)
      @key_size = key_size
      @block_size_bits  = 128
      @block_size_bytes = 16
    end

    # NOTE convert ECB encryption to AES gem or both to openssl
    def decipher_ecb(key,input,strip_padding: true)
      plain = decipher_ecb_blockwise(CryptBuffer(key),CryptBuffer(input).chunks_of(@block_size_bytes)).to_crypt_buffer
      strip_padding ? plain.strip_padding : plain
    end

    def encipher_ecb(key,input)
      encipher_ecb_blockwise(CryptBuffer(key),pad_message(input).chunks_of(@block_size_bytes))
    end
    
    def encipher_cbc(key_str,input_str,iv: nil)
      unicipher_cbc(:encipher,key_str,pad_message(input_str),iv)
    end
    
    def decipher_cbc(key_str,input_str,iv: nil,strip_padding: true)
      plain = unicipher_cbc(:decipher,key_str,CryptBuffer(input_str),iv).to_crypt_buffer
      strip_padding ? plain.strip_padding : plain
    end


    private

    def pad_message(input)
      buffer=CryptBuffer(input)
      final_block_size = buffer.length % @block_size_bytes
      delta = @block_size_bytes - final_block_size
      if delta > 0
        buffer.pad(delta)
      else
        buffer
      end
    end
    
    def pad_block(block)
      return block
    end
    
    def encipher_ecb_blockwise(key,blocks)
      blocks.map{|block| encipher_ecb_block(key,block)  }.join 
    end

    def encipher_ecb_block(key,block)
      _,out = AES.encrypt(block.str, key.hex, {:format => :plain,:padding => false,:cipher => "AES-#{@key_size}-ECB"})
      out
    end

    def decipher_ecb_blockwise(key,blocks)
      blocks.map{|block| decipher_ecb_block(key,block)  }.join 
    end

    def decipher_ecb_block(key,block)
      need_padding = (block.length < @block_size_bytes)
      AES.decrypt(["",block.str], key.hex, {:format => :plain,:padding => need_padding,:cipher => "AES-#{@key_size}-ECB"})
    end
    
    # this method is used for encipher and decipher since most of the code is identical
    # only the value of the previous block and the internal ecb method differs
    def unicipher_cbc(direction,key_str,input_buf,iv)

      method="#{direction.to_s}_cbc_block"
      blocks = input_buf.chunks_of(@block_size_bytes)
      iv   ||= blocks.shift.str
      key    = CryptBuffer(key_str).hex
      
      prev_block=iv.to_crypt_buffer

      strings = blocks.map.with_index do |block,i|
        ctext_block = send(method,key,block,prev_block)
        if direction == :encipher
          prev_block  = ctext_block
        else
          prev_block  = block
        end

        ctext_block.str
      end

      CryptBuffer(strings.join)
    end
    
    def encipher_cbc_block(key,block,prev_block)
      xored =  block ^ prev_block

      _,out = AES.encrypt(xored.str, key, {:format => :plain,:padding => false,:cipher => "AES-#{@key_size}-ECB",:iv => prev_block.str })
      ecb_block = CryptBuffer(out)
    end
    
    def decipher_cbc_block(key,block,prev_block)

      out = ::AES.decrypt([prev_block.str,block.str] , key, {:format => :plain,:padding => false,:cipher => "AES-#{@key_size}-ECB",:iv => prev_block.str })
      ecb_block = CryptBuffer(out)

      xored = ecb_block ^ prev_block
    end
    
  end
end

