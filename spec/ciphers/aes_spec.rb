require 'spec_helper'

RSpec.describe Ciphers::Aes do
  
  context "CBC" do
    let(:key)        { "YELLOW SUBMARINE" }
    let(:iv)         { (1..16).map{|_| 0.chr }.to_a.join }
    let(:subject)    { Ciphers::Aes.new }
    let(:plaintext)  { "1-2-3-4-5-6-7-8-9: Mary had a little lamb, His fleece was white as snow, And everywhere that Mary went, The lamb was sure to go."  }
    let(:unaligned)  { "Mary had a little lamb, His fleece was white as snow, And everywhere that Mary went, The lamb was sure to go."  }
    let(:ciphertext) {
      [36, 83, 146, 122, 110, 37, 2, 33, 135, 120, 30, 7, 109, 44, 81, 38, 166, 250, 138, 17, 34, 247, 53, 103, 248, 6, 53, 238, 107, 44, 23, 193, 18, 143, 119, 111, 112, 82, 195, 33, 35, 249, 126, 239, 238, 1, 163, 144, 31, 26, 64, 12, 28, 45, 50, 83, 214, 137, 34, 200, 43, 254, 68, 228, 156, 46, 172, 4, 19, 50, 19, 137, 253, 136, 137, 30, 33, 31, 238, 240, 245, 160, 24, 75, 196, 92, 179, 31, 51, 54, 180, 79, 140, 75, 9, 229, 130, 143, 116, 58, 231, 186, 74, 195, 145, 105, 165, 197, 98, 3, 40, 38, 55, 219, 125, 127, 68, 217, 205, 247, 222, 30, 226, 233, 97, 179, 145, 32, 75, 162, 144, 239, 20, 203, 145, 68, 91, 50, 38, 73, 167, 53, 13, 176]
    }

    context "#encipher_cbc" do
      it "can encrypt using cbc mode" do
        expect(subject.encipher_cbc(key,plaintext,iv: iv).bytes).to eq(ciphertext)
      end
    end
    
    context "#decipher_cbc" do
      it "#cbc_decrypt" do
        input = CryptBuffer(ciphertext).str
        expect(subject.decipher_cbc(key,input,iv: iv).str).to eq(plaintext)
      end
    end
    
    it "satisfies consistency equasion" do
      expect(subject.decipher_cbc(key,
                                  subject.encipher_cbc(key,plaintext,iv: iv).str,
                                  iv: iv).str).to eq(plaintext)
    end
    
    it "satisfies the consistency equasion if padding is required" do
      expect(subject.decipher_cbc(key,
                                  subject.encipher_cbc(key,unaligned,iv: iv).str,
                                  iv: iv).str).to eq(unaligned)
    end
  end

  
end

