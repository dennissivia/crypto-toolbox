module CryptoToolbox
  module Oracles
    module PaddingOracle
      
      class PlaintextSelection
        PLAIN_TEXTS= %w(
MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
).freeze
        def self.sample
          samples.sample
        end
        def self.samples
          PLAIN_TEXTS
        end
      end
      
      class MemoryOracle
        attr_reader :secret_plaintext # for result validation only. I can trust myself
        
        def initialize
          @key   = SecureRandom.random_bytes(16)
          @iv    = SecureRandom.random_bytes(16)
          @secret_plaintext = CryptBuffer.from_base64(PlaintextSelection::sample).str
        end

        def sample_ciphertext
          @ciphertext ||= generate_ciphertext
        end
        
        def connect; end
        def disconnect; end
        
        def valid_padding?(input,custom_block_amount=nil)
          # openssl will throw on invalid padding
          begin
            block  = CryptBuffer(input)
            result = CryptBuffer(decrypt(block))
            result.validate_padding!
          rescue CryptBufferConcern::Padding::InvalidPkcs7Padding => ex
            false
          end
        end

        private

        def generate_ciphertext
          CryptBuffer(@iv + Ciphers::Aes.new.encipher_cbc(@key,@secret_plaintext,iv: @iv).str).hex
        end

        def decrypt(msg)
          Ciphers::Aes.new.decipher_cbc(@key,msg,iv: @iv,strip_padding: false)
        end
        
        def check_padding(msg)
          
        end
      end
    end
  end
end
