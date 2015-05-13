module CryptBufferConcern
  module Arithmetic
    
    def modulus(mod)
      real_mod = sanitize_modulus(mod)
      CryptBuffer( bytes.map{|b| b % real_mod } )
    end

    def mod_sub(n,mod: 256)
      tmp = bytes.map do |byte|
        val = byte.to_bn.mod_sub(n,mod).to_i
      end
      CryptBuffer(tmp)
    end

    def sub(n)
      CryptBuffer( bytes.map{|byte| byte -n } )
    end
    
    def add(n, mod: 256, offset: 0)
      real_mod = [256,mod].min

      tmp = bytes.map do |b|
        val = (b + n) % real_mod
        val >= offset ? val : val+offset
      end
      CryptBuffer(tmp)
    end

    def hdist(other,normalize: false)
      if normalize
        hamming_distance(other) / length.to_f
      else
        hamming_distance(other)
      end
    end

    private

    def hamming_distance(other)
      (self ^ other).bits.join.count("1") 
    end
    
    def sanitize_modulus(mod)
      (mod > 0) ? mod : 256
    end

  end
end
