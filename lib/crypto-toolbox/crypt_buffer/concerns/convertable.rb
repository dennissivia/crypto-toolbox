module CryptBufferConcern
  module Convertable
    def hex
      bytes2hex(bytes).upcase
    end
    
    alias_method :h, :hex
    
    def chars
      map(&:chr)
    end
    alias_method :c, :chars
    
    def str
      map(&:chr).join
    end
    alias_method :s, :str

    def bits
      map{|b| "%08d" % b.to_s(2) }
    end

    def to_s
      str
    end

    def base64(strict: true)
      strict ?  Base64.strict_encode64(str) : Base64.encode64(str) 
    end

    private
    def bytes2hex(bytes)
      bytes.map{|b| b.to_s(16)}.map{|hs| hs.length == 1 ? "0#{hs}" : hs  }.join
    end
  end
end

module CryptBufferConcern
  module TypeExtension
    def to_crypt_buffer
      CryptBuffer(self)
    end
  end
end

String.send(:include, CryptBufferConcern::TypeExtension)
Fixnum.send(:include, CryptBufferConcern::TypeExtension)
 Array.send(:include, CryptBufferConcern::TypeExtension)



