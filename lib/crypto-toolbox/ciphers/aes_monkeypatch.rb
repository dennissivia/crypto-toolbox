# Monkey patch the dependency to fix https://github.com/chicks/aes/issues/17
module AES
  class AES
      # Create a new cipher using the cipher type specified
      def _setup(action)
        @cipher ||= OpenSSL::Cipher.new(@options[:cipher])
        # Toggles encryption mode
        @cipher.send(action)
        @cipher.padding = @options[:padding]
        @cipher.key = @key.unpack('a2'*@cipher.key_len).map{|x| x.hex}.pack('c'*@cipher.key_len)
      end
  end
end
