require 'spec_helper'

describe CryptBuffer do
  let(:short){ CryptBuffer(1)    } 
  let(:mid)  { CryptBuffer("0xaAbB") }
  let(:long) { CryptBuffer("The House")  }
  let(:empty){ CryptBuffer([])   }
  let(:buffer){ CryptBuffer([1,10,100,200,245])  }
  
  context "#bytes" do
    it "gives access to the byte repreesntation" do
      expect(CryptBuffer(0x0F).bytes).to eq([15])
    end
  end

  context "#nth_bit" do
    it "returns an array of the nths bits of its bytes" do
      expect((buffer).nth_bits(0)).to eq([1,0,0,0,1])
    end
    it "fails on negative indices" do
      expect{(buffer).nth_bits(-1)}.to raise_error(CryptBuffer::OutOfRangeError)
    end
    it "fails on too high indices" do
      expect{(buffer).nth_bits(8)}.to raise_error(CryptBuffer::OutOfRangeError)
    end
  end

  context "#nth_byte" do
    let(:buffer)      { CryptBuffer((1..15).to_a)  }
    let(:third_bytes) { CryptBuffer([1,4,7,10,13])  }
    let(:third_bytes2) { CryptBuffer([3,6,9,12,15])  }
    
    it "returns an empty buffer on 0 input" do
      expect((buffer).nth_bytes(0)).to eq(empty)
    end
    it "returns an empty buffer on nil input" do
      expect((buffer).nth_bytes(0)).to eq(empty)
    end
    it "returns an empty buffer on negative input" do
      expect((buffer).nth_bytes(0)).to eq(empty)
    end
    it "returns the nth byts" do
      expect((buffer).nth_bytes(3)).to eq(third_bytes)
    end
    it "returns the nth byts starting at a given offset" do
      expect((buffer).nth_bytes(3,offset: 2)).to eq(third_bytes2)
    end
  end

  context "#from_base64" do
    let(:input) { "c2VjcmV0IG1lc3NhZ2U=" }
    let(:input_newline) { "c2VjcmV0I\nG1lc3NhZ2U=" }
    let(:plain) { "secret message" }

    it "can parse valid base64 encoded strings" do
      expect(CryptBuffer.from_base64(input).str). to eq(plain)
    end
    it "support \n separated base64" do
      expect(CryptBuffer.from_base64(input_newline).str). to eq(plain)
    end
  end
  
  context "#from_hex" do
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




