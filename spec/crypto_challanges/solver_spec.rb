require 'spec_helper'


RSpec.describe CryptoChallanges::Solver do

  context "#solve1" do
    let(:input)  { "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d" }
    let(:output) { "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" }
    it "solves the challange" do
      expect(subject.solve1(input)).to eq(output)
    end
  end
  
  context "solve2" do
    let(:c1)     { "1c0111001f010100061a024b53535009181c" }
    let(:c2)     { "686974207468652062756c6c277320657965" }
    let(:output) { "746865206b696420646f6e277420706c6179" }
    it "solves the challange" do
      expect(subject.solve2(c1,c2)).to eq(output)
    end
  end
  
  context "solve3" do
    let(:input) { "746865206b696420646f6e277420706c6179" }
    it "solves the challange" do
      expect(subject.solve3(input)).to eq("the kid don't play")
    end
  end

  context "solve4" do
    let(:input) { File.read("challanges/cryptopals/set1-challange4.txt").split("\n") }
    it "solves the challange" do
      expect(subject.solve4(input)).to eq("Now that the party is jumping\n")
    end
  end

  context "solve5" do
    let(:key)       { "ICE" }
    let(:input)     { "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal" }
    let(:output)    { "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".upcase }

    
    it "solves the challange " do
      expect(subject.solve5(input,key)).to eq(output)
    end
  end

  context "challange6"  do
    let(:input) { File.read("challanges/cryptopals/set1-challange6.txt") }
    let(:plain) { "I'm back and I'm ringin' the bell" }
    it "solves the challange" do
      expect(subject.solve6(input).first.str).to include(plain)
    end
  end
  
  context "challange7" do
    let(:key)   { "YELLOW SUBMARINE" }
    let(:input) { File.read("challanges/cryptopals/set1-challange7.txt") }
    let(:plain) { "I'm back and I'm ringin' the bell" }

    it "solves the challange" do
      expect(subject.solve7(input,key)).to include(plain)
    end
  end

  context "challange8" do
    let(:input)  { File.read("challanges/cryptopals/set1-challange8.txt").split("\n").map{|c| CryptBuffer.from_hex(c)} }
    let(:result_index) { 132 }
    let(:result_msg)   { "D880619740A8A19B7840A8A31C810A3D08649AF70DC06F4FD5D2D69C744CD283E2DD052F6B641DBF9D11B0348542BB5708649AF70DC06F4FD5D2D69C744CD2839475C9DFDBC1D46597949D9C7E82BF5A08649AF70DC06F4FD5D2D69C744CD28397A93EAB8D6AECD566489154789A6B0308649AF70DC06F4FD5D2D69C744CD283D403180C98C8F6DB1F2A3F9C4040DEB0AB51B29933F2C123C58386B06FBA186A"  }

    it "finds the correct index" do
      expect(subject.solve8(input).first).to eq(result_index)
    end
    
    it "contains the correct ciphertext" do
      expect(subject.solve8(input)[1].hex).to eq(result_msg)
    end
  end

  context "challange9" do
    let(:input)  { "YELLOW SUBMARINE" }
    let(:output) { "YELLOW SUBMARINE\x04\x04\x04\x04" }
    
    it "is solved" do
      expect(subject.solve9(input)).to eq(output)
    end
  end


  context "challange10" do
    let(:key)        { "YELLOW SUBMARINE" }
      let(:iv)         { (1..16).map{|_| 0.chr }.to_a.join }

    context "AES class works properly" do
      let(:aes){ Ciphers::Aes.new(128,:ECB) }
      let(:plaintext)  { "1-2-3-4-5-6-7-8-9: Mary had a little lamb, His fleece was white as snow, And everywhere that Mary went, The lamb was sure to go."  }
      let(:ciphertext) {
        [36, 83, 146, 122, 110, 37, 2, 33, 135, 120, 30, 7, 109, 44, 81, 38, 166, 250, 138, 17, 34, 247, 53, 103, 248, 6, 53, 238, 107, 44, 23, 193, 18, 143, 119, 111, 112, 82, 195, 33, 35, 249, 126, 239, 238, 1, 163, 144, 31, 26, 64, 12, 28, 45, 50, 83, 214, 137, 34, 200, 43, 254, 68, 228, 156, 46, 172, 4, 19, 50, 19, 137, 253, 136, 137, 30, 33, 31, 238, 240, 245, 160, 24, 75, 196, 92, 179, 31, 51, 54, 180, 79, 140, 75, 9, 229, 130, 143, 116, 58, 231, 186, 74, 195, 145, 105, 165, 197, 98, 3, 40, 38, 55, 219, 125, 127, 68, 217, 205, 247, 222, 30, 226, 233, 97, 179, 145, 32]
      }
      
      it "#cbc_encrpyt" do
        expect(aes.encipher_cbc(key,plaintext,iv: iv).bytes).to eq(ciphertext)
      end
      
      it "#cbc_decrypt" do
        input = CryptBuffer(ciphertext).str
        expect(aes.decipher_cbc(key,input,iv: iv).str).to eq(plaintext)
      end
      
      it "satisfies consistency equasion" do
        expect(aes.decipher_cbc(key,
                                aes.encipher_cbc(key,plaintext,iv: iv).str,
                                iv: iv).str).to eq(plaintext)
      end
    end
    
    context "challange" do
      let(:input)  { File.read("challanges/cryptopals/set2-challange10.txt")}
      let(:result) { "I'm back and I'm ringin' the bell" }
      
      it "solves challange 10" do
        expect(subject.solve10(key,input,iv)).to include(result)
      end
    end
    
  end
end



