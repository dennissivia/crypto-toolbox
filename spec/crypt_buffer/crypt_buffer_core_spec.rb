require 'spec_helper'

describe CryptBuffer do
  let(:short){ CryptBuffer(1)    } 
  let(:mid)  { CryptBuffer("0xaAbB") }
  let(:long) { CryptBuffer("The House")  }
  let(:empty){ CryptBuffer([])   }
  
  context "#bytes" do
    it "gives access to the byte repreesntation" do
      expect(CryptBuffer.new(0x0F).bytes).to eq([15])
    end
  end

  context "nth_bits" do
    let(:buffer){ CryptBuffer([1,10,100,200,245])  }
                  
    it "returns an array of the nths bits of its bytes" do
      expect((buffer).nth_bits(0)).to eq([1,0,0,0,1])
    end
    it "fails on negative indices" do
      expect{(buffer).nth_bits(-1)}.to raise_error(CryptBuffer::OutOfRangeError)
    end
    it "fails on too high indices" do
      expect{(buffer).nth_bits(8)}.to raise_error(CryptBuffer::OutOfRangeError)
    end
    it "interprets a hextring with 0x as hex string" do
      expect(CryptBuffer.from_hex("ef").hex).to eq("EF")
    end

    it "interprets a hexstring wihtout 0x as hexstring" do
      expect(CryptBuffer.from_hex("0xef").hex).to eq("EF")
    end
    
    it "handles nil properly" do
      expect(CryptBuffer.from_hex(nil).hex).to eq("")
    end

    it "supports single char inputs" do
      expect(CryptBuffer.from_hex("f").hex).to eq("0F")
    end
  end

  context "#read_hex reads hex data from IO"
end




