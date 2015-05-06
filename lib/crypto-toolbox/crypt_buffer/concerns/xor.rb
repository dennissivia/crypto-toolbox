module CryptBufferConcern
  module Xor


    def ^(other)
      xor(other)
    end
    
    def xor_at(input,pos)
      return self if input.nil? || (pos.abs > length)

      case input.respond_to?(:to_ary)
      when true
        # map our current data to xor all inputs with the given bytepos.
        # all other bytes are kept as they were
        abs_pos = normalize_pos(pos)
        tmp = bytes.map.with_index{|b,i| i == abs_pos ? xor_multiple(b,input.to_ary) : b }
        CryptBuffer(tmp)
      else
        tmp = bytes
        tmp[pos] = tmp[pos] ^ input
        CryptBuffer(tmp)
      end 
    end
    
    def xor(input,expand_input: false)
      if expand_input
        xor_all_with(input)
      else
        xor_bytes(CryptBuffer(input).bytes)
      end
    end

    def xor_all_with(input)
      expanded = expand_bytes(CryptBuffer(input).bytes,self.bytes.length)
      xor_bytes(expanded)
    end

    def xor_space
      xor(0x20,expand_input: true)
    end
    private
    
    def xor_bytes(byt)
      len = [self.bytes.size,byt.size].min
      result = self.bytes[0...len].map.with_index{|b,i| b ^ byt[i] } + self.bytes[len,self.bytes.length - len]
      self.class.new(result)
    end

    def xor_hex(hex)
      x = hex2bytes(hex)
      xor_bytes(x)
    end

    private
    def xor_multiple(byte,bytes)

      ([byte] + bytes).reduce(:^)
    end
    def normalize_pos(pos)
      (pos < 0) ? (length() + pos ) : pos
    end

    
  end
  
end
