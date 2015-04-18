module CryptBufferConcern
  module PrettyPrint
    def pp
      puts pretty_hexstr
    end
    
    private
    def pretty_hexstr
      str = h.scan(/.{2}/).to_a.join(" ")
      "0x#{h.upcase} (#{str.upcase})"
    end
  end
end
