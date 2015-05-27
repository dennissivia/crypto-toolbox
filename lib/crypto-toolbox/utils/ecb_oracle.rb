module Utils
  class EcbOracle
    attr_reader :mode,:prefix,:suffix
    
    def initialize(static_key: nil,static_mode: nil,block_size: 128,static_prefix: nil,static_suffix: nil,append: false, prepend: false)
      @key  = CryptBuffer(static_key)
      @mode = static_mode
      @iv   = nil
      @c    = nil
      @block_size = block_size
      
      @append  = append
      @prepend = prepend
      @suffix = static_suffix
      @prefix = static_prefix
    end
    
    def encipher(plaintext)
      #support reproducable keys and mode
      @key      ||= CryptBuffer.random(16)
      @mode     ||= [:cbc,:ecb][SecureRandom.random_number(2)]
      message   = pad_message(plaintext) 
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
      @prefix ||= SecureRandom.random_bytes(lpad_size)
      @suffix ||= SecureRandom.random_bytes(rpad_size)

      # NOTE PLEASE rewrite ME !!!
      msg = @prefix + msg if prepend?
      msg = msg + @suffix if append?
      
      msg
    end
    
    def encipher_cbc(plaintext)
      @iv     = CryptBuffer.random(16)
      crypter = Ciphers::Aes.new
      crypter.send(:encipher_cbc,@key,plaintext,iv: @iv.str)
    end
    
    def encipher_ecb(plaintext)
      crypter = Ciphers::Aes.new
      crypter.send(:encipher_ecb,@key,plaintext)
    end

    private
    def append?
      @append == true
    end
    def prepend?
      @prepend == true
    end
    
  end
end
