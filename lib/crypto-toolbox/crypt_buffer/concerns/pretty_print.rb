module CryptBufferConcern
  module PrettyPrint
    def pp
      puts pretty_hexstring
    end
    
    def pretty_hexstring
      str = h.scan(/.{2}/).to_a.join(" ")
      "0x#{h.upcase} (#{str.upcase})"
    end
  end
end
