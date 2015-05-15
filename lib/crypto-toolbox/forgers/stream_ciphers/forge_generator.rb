
module Forgers
  module StreamCipher
    # This class generates a forged ciphertext that has been constructed
    # to decipher to a specific and specified forged plaintext.
    # It receives a observed orginal ciphertext c, its (partial or full) plaintext
    # and the plaintext the attacker would like to have.
    # It returns the ciphertext that correcponds to the forged message
    class ForgeGenerator
      
      # Create the xor of the two plaintext messages, that can also just be a
      # part of the real message or have some pseudo padding for any unknown position
      # finally xor that difference of the plaintexts at the correct position of the
      # ciphertext
      def forge(ciphertext,plaintext,target_plaintext)
        diff = CryptBuffer(plaintext).xor(target_plaintext)
        c    = CryptBuffer.from_hex(ciphertext)
        c.xor(diff)
      end
      
      def self.forge(ciphertext,plaintext,target_plaintext)
        new.forge(ciphertext,plaintext,target_plaintext)
      end
    end
  end
end
