require 'spec_helper'

describe CryptBuffer do
  let(:short){ CryptBuffer(1)    } 
  let(:mid)  { CryptBuffer("0xaAbB") }
  let(:long) { CryptBuffer("The House")  }
  let(:empty){ CryptBuffer([])   }
  
  context "#modulize" do
    it "converts every byte into a value given mod n, with n given" do
      expect(CryptBuffer("0x0f0f0f").modulus(10).hex).to eq("050505")
    end
    it "ignores 0 modulus" do
      expect(CryptBuffer("0x0f0f0f").modulus(0).hex).to eq("0F0F0F")
    end
    it "ignores negativ modulus" do
      expect(CryptBuffer("0x0f0f0f").modulus(-2).hex).to eq("0F0F0F")
    end
  end
  
  context "#add" do
    it "adds an integer value mod 256 per default" do
      expect(CryptBuffer("0xfefe").add(1).hex).to eq("FFFF")
    end
    it "properly wraps around by the modulus" do
      expect(CryptBuffer("0xfefe").add(2).hex).to eq("0000")
    end
    it "adds ad integer value mod n, with n given" do
      expect(CryptBuffer("0x0f").add(15,mod:20).bytes).to eq([10])
    end
    it "ignores mod: > 256" do
      expect(CryptBuffer("0xfefe").add(2,mod: 300).hex).to eq("0000")
    end

    it "can be used to shift plain language latters by the offset" do
      expect(CryptBuffer("ABCDEFGH").add(3,mod: 90).str).to eq("DEFGHIJK")
    end
    it "accepts an offset to start with on every wrap around" do

      expect(CryptBuffer("W").add(3,mod: 91,offset: 65).str).to eq("Z")
    end
    it "accepts an offset to start with on every wrap around" do
      expect(CryptBuffer("ABCXYZ").add(3,mod: 91,offset: 65).str).to eq("DEFABC")
    end

    it "can be used as a ceasar cipher" do
      plain="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      cipher="DEFGHIJKLMNOPQRSTUVWXYZABC"
      shift=3
      expect(CryptBuffer(plain).add(shift,mod: 91,offset: 65).str).to eq(cipher)
    end
  end
  
  context "#hdist (hamming distance)" do
    let(:string1)  { "this is a test" }
    let(:string2)  { "wokka wokka!!!" }
    let(:distance) { 37 }
    
    it "calculates the hamming distance" do
      expect(CryptBuffer(string1).hdist(CryptBuffer(string2))).to eq(distance)
    end
    
    it "accepts strings as input" do
      expect(CryptBuffer(string1).hdist(string2)).to eq(distance)
    end

    it "can calculate a normalized version" do
      expect(CryptBuffer(string1).hdist(string2,normalize: true)).to eq(2.642857142857143)
    end
    
  end
end

