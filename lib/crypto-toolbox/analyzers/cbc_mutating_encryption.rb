module CryptoToolbox
  module Analyzers
    class CbcMutatingEncryption
      attr_reader :oracle
      def initialize(oracle)
        @oracle = oracle
      end

      def assemble_attack_message
        # we are lazy thus we use 0 as a byte which is neutral to xor,
        # thus we dont have to cancel it before adding admin=true. 
        input = "\0" * 32
        blocks = @oracle.encrypted_message_for(input).chunks_of(16)
        fake   = blocks[2].xor(";admin=true;",expand_input: false )
        blocks[2] = fake
        ciphertext = blocks.map(&:str).join
      end
    end
  end
end
