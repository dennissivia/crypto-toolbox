
module Matasano
  module Sets
    module Set2
      def solve9(input)
        CryptBuffer(input).pad(4).str
      end

      def solve10(key,input,iv)
        data  = CryptBuffer.from_base64(input).str
        Ciphers::Aes.new.decipher_cbc(key,data,iv: iv).str
      end
      
      def solve11(oracle,plaintext)
        puts "see tests"
      end
      
      def solve12(oracle)
        Analyzers::EcbStringAppender.new(oracle).analyze
      end

      def solve13(key = SecureRandom.random_bytes(16) )
        oracle = CryptoToolbox::Oracles::UserProfileEncryptionOracle.new(key)
        
        # blocks:
        # 1) email=[...]@xy.
        # 2) com&uid=10&role=
        # 3) (guest|admin)[...]

        block_size        = 16
        prefix            = "email="
        infix             = "&uid=10&role="
        email_suffix      = "@xy.com" 
        email_user_length = (2*block_size) - (prefix.length + infix.length + email_suffix.length)
        email_user        = ("a".."z").to_a.sample(email_user_length).join
        email_address     = email_user + email_suffix
        ciphertext        = oracle.encrypted_profile_for(email_address)

        # take the first to blocks of the meassage to have a ciphertext of everything up until role=
        forgery_blocks,_  = ciphertext.to_crypt_buffer[0,2*block_size]

        # Construct a ciphertext containinig three blocks, where the last block
        # only contains admin...... where . is a valid padding:
        # 1: email=aaaaaaaaaa
        # 2: admin...........    . = 0xb
        # 3: @whatever.com
        target_role         = "admin"
        padding_length      = (block_size - target_role.length())
        malicious_username  = "aaaaaaaaaa#{target_role}".to_crypt_buffer.pad(padding_length).str + email_suffix
        ciphertext2         = oracle.encrypted_profile_for(malicious_username)
        role_chunk          = ciphertext2[block_size,block_size]

        oracle.decrypt_profile(forgery_blocks.str + role_chunk)
      end

      def solve14(oracle)
        Analyzers::EcbStringAppender.new(oracle).analyze
      end

      def solve15(input)
        CryptBuffer(input).strip_padding!.str
      end
    end
  end
end
