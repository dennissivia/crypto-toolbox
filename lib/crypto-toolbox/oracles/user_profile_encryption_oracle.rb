module CryptoToolbox
  module Oracles
    class UserProfileEncryptionOracle
      def initialize(key = SecureRandom.random_bytes(16) )
        @key = key
      end

      def profile_for(email)
        email.gsub!(/[&=]/,"") # sanitize meta chars
        "email=#{email}&uid=10&role=guest"
      end
    
      def parse_profile(string)
        string.split("&").each_with_object({}){|pair,hsh| k,v = pair.split("="); hsh[k.to_sym] = v }
      end
      
      def encrypted_profile_for(email)
        Ciphers::Aes.new.encipher_ecb(@key,profile_for(email))
      end

      def decrypt_profile(ciphertext)
        plaintext = Ciphers::Aes.new.decipher_ecb(@key,ciphertext).to_crypt_buffer.strip_padding.str
        parse_profile(plaintext)
      end

    end
  end
end
