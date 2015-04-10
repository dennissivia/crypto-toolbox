module Ciphers
  class Rot13
    def self.apply(msg)
      ::Ciphers::Rot13.new.apply(msg)
    end
    def self.encipher(msg)
      ::Ciphers::Rot13.new.apply(msg)
    end
    def self.decipher(msg)
      ::Ciphers::Rot13.new.apply(msg)
    end

    def apply(message)
      ::Ciphers::Caesar.encipher(message,"N")
    end
    def encipher(message)
      apply(message)
    end

    def decipher(message)
      apply(message)
    end
  end
end
