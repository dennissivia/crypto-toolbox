module CryptBufferConcern
  module Convertable
    def hex
      bytes2hex(bytes).upcase
    end
    
    alias_method :h, :hex
    
    def chars
      map{|b| b.to_i.chr}
    end
    alias_method :c, :chars
    
    def str
      chars.join
    end
    alias_method :s, :str

    def bits
      map{|b| "%08d" % b.to_s(2) }
    end

    def to_s
      str
    end
    private
    def bytes2hex(bytes)
      bytes.map{|b| b.to_s(16)}.map{|hs| hs.length == 1 ? "0#{hs}" : hs  }.join
    end
  end
end
