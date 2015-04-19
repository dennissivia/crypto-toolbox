require 'spec_helper'

describe CryptBuffer do
  let(:short){ CryptBuffer(1)    } 
  let(:mid)  { CryptBuffer("0xaAbB") }
  let(:long) { CryptBuffer("The House")  }
  let(:empty){ CryptBuffer([])   }
  
  context "#xor_space" do
    it "provides a shorthand to xor a whitespace" do
      expect(short.xor_space).to eq(short.xor(" "))
    end
  end
  context "#xor" do
    it "xors a single byte with a single byte input" do
      expect(short.xor(255)).to eq(254)
    end
    
    context "conversion" do
      it "accepts an integer" do
        expect(short.xor(255)).to eq(254)
      end
      it "accepts a hex-integer" do
        expect(short.xor(0xFF)).to eq(254)
      end
      it "accepts a string" do
        expect(short.xor(" ").str).to eq("!")
      end
      it "accepts a hex-string" do
        expect(short.xor("0xFF")).to eq(254)
      end
      it "accepts a string" do
        expect(long.xor("   a     ").str).to eq("tHEAhOUSE")
      end
    end
    context ",expand argument" do
      it "xors a multi byte buffer with a sinble input" do
        expect(mid.xor(1,expand_input: true)).to eq([171,186])
      end
      it "xors a long buffer with a multiby shorter buffer" do
        expect(long.xor(" ",expand_input: true).str).to eq("tHE\x00hOUSE")
      end
      it "xors a only the first byte of the buffer, if expand_input is false" do
        expect(long.xor(" ",expand_input: false).str).to eq("the House")
      end
      it "does not expand int input, if expand_input is not set" do
        expect(long.xor(" ",expand_input: false).str).to eq("the House")
      end
    end
    
  end
  context "#xor_at(val,pos)" do
    let(:buf){ CryptBuffer([1,1,2,2,3,3]) }

    it "xors the byte at the given position" do
      expect(buf.xor_at(200,0).bytes).to eq([201,1,2,2,3,3])
    end
    it "supports valid negative indices" do
      expect(buf.xor_at(200,-1).bytes).to eq([1,1,2,2,3,203])
    end
    it "ignores invalid negative indices" do
      expect(buf.xor_at(200,-100).bytes).to eq([1,1,2,2,3,3])
    end
    it "supports the maximum negative index" do
      expect(buf.xor_at(200,-6).bytes).to eq([201,1,2,2,3,3])
    end
    it "does nothing if the index is over the upper bound" do
      expect(buf.xor_at(200,200).bytes).to eq([1,1,2,2,3,3])
    end
    context "#xor_at([x,..],pos)" do
      it "supports array index to do multiple xors" do
        expect(buf.xor_at([5,15],0).bytes).to eq([11,1,2,2,3,3])
      end
      it "supports empty arrays" do
        expect(buf.xor_at([],0).bytes).to eq([1,1,2,2,3,3])
      end
      it "handles nil" do
        expect(buf.xor_at(nil,0).bytes).to eq([1,1,2,2,3,3])
      end
    end
  end

  context "#xor_all_with as shorthand for xor(val,expand = true)" 
end
