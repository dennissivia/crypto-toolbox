module Utils
  class EcbOracle
    attr_reader :mode
    
    def initialize
      @key  = nil
      @iv   = nil
      @c    = nil
      @mode = nil
    end
    
    def encipher(plaintext,random_pads: false)
      @key      = CryptBuffer.random(16)
      @mode     = [:cbc,:ecb][SecureRandom.random_number(2)]
      message   = random_pads ? pad_message(plaintext) : plaintext
      
      method  = "encipher_#{@mode}".to_sym
      # we dispatch the method to avoid if-else dispatches
      # due to the difference of IV usage
      @c = send(method,message)
    end

    private
    
    def pad_message(msg)
      pad_range = (5..10).to_a
      lpad_size = pad_range.sample
      rpad_size = pad_range.sample
      lpad      = SecureRandom.random_bytes(lpad_size)
      rpad      = SecureRandom.random_bytes(rpad_size)
      
      lpad + msg + rpad
    end
    
    def encipher_cbc(plaintext)
      @iv     = CryptBuffer.random(16)
      crypter = Ciphers::Aes.new(128)
      crypter.send(:encipher_cbc,@key,plaintext,iv: @iv.str)
    end
    
    def encipher_ecb(plaintext)
      crypter = Ciphers::Aes.new(128)
      crypter.send(:encipher_ecb,@key,plaintext)
    end
    
  end
end
