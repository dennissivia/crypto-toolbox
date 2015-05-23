
module CryptoChallanges
  module Sets
    module Set1
      def solve1(input)
        CryptBuffer.from_hex(input).base64
      end
      
      def solve2(c1,c2)
        (CryptBuffer.from_hex(c1) ^ CryptBuffer.from_hex(c2)).hex.downcase
      end
      
      def solve3(input)
        candidates = (1..256).map{ |guess| CryptBuffer.from_hex(input).xor_all_with(guess) }
        detector = Analyzers::Utils::HumanLanguageDetector.new
        
        detector.human_language_entries(candidates).first.to_s
      end

      # challange:
      # One of the 60-character strings in this file has been encrypted by single-character XOR.
      def solve4(hexstrings)
        detector = Analyzers::Utils::HumanLanguageDetector.new
        result = hexstrings.map{|h| CryptBuffer.from_hex(h)}.map.with_index do |c,i|
          candidates = (1..256).map{ |guess| c.xor_all_with(guess) }
          matches = detector.human_language_entries(candidates)

          matches.empty? ? nil : matches
        end
        result.flatten.compact.map(&:str).first
      end
      
      def solve5(input,key)
        CryptBuffer(input).xor(key,expand_input: true).hex
      end

      def solve6(input)
        buffer = CryptBuffer.from_base64(input)
        Analyzers::VigenereXor.new.analyze(buffer.hex,Analyzers::VigenereXor::HammingDistanceKeyLengthFinder.new)
      end

      def solve7(input,key)
        data = CryptBuffer.from_base64(input).str
        Ciphers::Aes.new.decipher_ecb(key,data)
      end

      def solve8(ciphers)
        Utils::EcbDetector.new.detect(ciphers).first
      end
    end

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
      
      def solve12(oracle,suffix=nil)
        Analyzers::EcbStringAppender.new(oracle).analyze
      end

      def solve13(key = SecureRandom.random_bytes(16) )
        @key = key        
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
        ciphertext        = encrypted_profile_for(email_address)

        forgery_blocks,_  = ciphertext.to_crypt_buffer[0,2*block_size]

        # Construct a block with admin...... where . is a valid padding:
        # 1: email=aaaaaaaaaa
        # 2: admin...........    . = 0xb
        # 3: @whatever.com

        target_role         = "admin"
        padding_length      = (block_size - target_role.length())
        malicious_username  = "aaaaaaaaaa#{target_role}".to_crypt_buffer.pad(padding_length).str + email_suffix
        ciphertext2         = encrypted_profile_for(malicious_username)
        role_chunk          = ciphertext2[block_size,block_size]

        result = decrypt_profile(forgery_blocks.str + role_chunk)
      end


      def profile_for(email)
        email.gsub!(/[&=]/,"") # sanitize meta chars
        "email=#{email}&uid=10&role=guest"
      end
    
      def parse_profile(string)
        string.split("&").each_with_object({}){|pair,hsh| k,v = pair.split("="); hsh[k.to_sym] = v }
      end
      
      private
      
      def encrypted_profile_for(email)
        Ciphers::Aes.new.encipher_ecb(@key,profile_for(email))
      end
      def decrypt_profile(ciphertext)
        plaintext = Ciphers::Aes.new.decipher_ecb(@key,ciphertext).to_crypt_buffer.strip_padding.str
        parse_profile(plaintext)
      end

    end
  end
  
  class Solver
    include CryptoChallanges::Sets::Set1
    include CryptoChallanges::Sets::Set2
  end
end
