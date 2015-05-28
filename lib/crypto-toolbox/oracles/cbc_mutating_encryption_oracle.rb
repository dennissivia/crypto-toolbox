module CryptoToolbox
  module Oracles
    class CbcMutatingEncryptionOracle
      attr_reader :prefix,:suffix

      
      def initialize(key = SecureRandom.random_bytes(16) )
        @key     = key
        @prefix  = "comment1=cooking%20MCs;userdata="
        @suffix  = ";comment2=%20like%20a%20pound%20of%20bacon"
        @iv      = SecureRandom.random_bytes(16)
      end

      #make sure this attack is not possible
      # fake_user="admin=true;admin=true;"
      # ciphertext = oracle.encrypted_message_for(fake_user)
      # oracle.is_admin?(ciphertext)
      def message_for(user)
        user.gsub!(/[;=]/,"") # sanitize meta chars
        @prefix + user + @suffix
      end
    
      def parse_message(string)
        string.split(";").each_with_object({}){|pair,hsh| k,v = pair.split("="); hsh[k.to_sym] = v }
      end
      
      def encrypted_message_for(user)
        Ciphers::Aes.new.encipher_cbc(@key,message_for(user),iv: @iv)
      end
      
      def is_admin?(ciphertext)
        data = decrypt_message(ciphertext)
        data.has_key?(:admin) && data[:admin] == "true"
      end
      
      private
      def decrypt_message(ciphertext)
        plaintext = Ciphers::Aes.new.decipher_cbc(@key,ciphertext,iv: @iv).to_crypt_buffer.strip_padding.str
        parse_message(plaintext)
      end

    end
  end
end
