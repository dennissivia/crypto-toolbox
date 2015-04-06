require_relative './../lib/crypt_buffer.rb'

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
  context "#initialize" do
    let(:value){ 32 }

    [0x20,"0x20"," ",32].each do |input|
      it "should accept a #{input} of type #{input.class}" do
        expect{CryptBuffer.new(input)}.to_not raise_error
      end
      it "converts input of type #{input.class} properly" do
        expect(CryptBuffer.new(input).bytes).to eq([value])
      end
      it "allows conversion via CryptBuffer()" do
        expect(CryptBuffer(input).bytes).to eq([value])
      end
    end
    it "supports multi digit hex integers" do
      expect(CryptBuffer(0xaabb).bytes).to eq([170,187])
    end
  end

  context "output conversion" do
      
    context "#hex" do
      it "returns a proper hex string" do
        # dont look case conversions into account
        expect(mid.hex.upcase).to eq("AABB")
      end
      it "returns upcased strings" do
        expect(mid.hex).to eq("AABB")
      end
      it "omits the 0x prefix" do
        expect(short.hex).to_not include("0x")
      end
      it "pads single digit values with a 0" do
        expect(short.hex).to eq("01")
      end
      it "supports empty input" do
        expect(empty.hex).to eq("")
      end
    end
    context "#bytes" do
      it "returns a byte array of the internal state" do
        expect(short.bytes).to eq([1])
      end
      it "returns all internal bytes" do
        expect(long.bytes).to eq([84, 104, 101, 32, 72, 111, 117, 115, 101])
      end
      it "returns [] for emtpy buffers" do
        expect(empty.bytes).to eq([])
      end
    end
    context "#bits" do
      it "returns a byte array of the internal state" do
        expect(short.bits).to eq(["00000001"])
      end
      it "returns all internal bytes as bitsets" do
        expect(mid.bits).to eq(["10101010", "10111011"])
      end
      it "returns [] for emtpy buffers" do
        expect(empty.bits).to eq([])
      end
    end
    
    context "#chars" do
      it "returns a char array of the internal state" do
        expect(short.chars).to eq(["\x01"])
      end
      it "returns all chars" do
        expect(long.chars).to eq(["T", "h", "e", " ", "H", "o", "u", "s", "e"])
      end
      it "returns [] for emtpy buffers" do
        expect(empty.chars).to eq([])
      end
    end

    context "#str" do
      it "returns a char array of the internal state" do
        expect(short.str).to eq("\x01")
      end
      it "returns all chars" do
        expect(long.str).to eq("The House")
      end
      it "returns '' for emtpy buffers" do
        expect(empty.str).to eq('')
      end
    end

    context "provides shorthand functions for output conversion" do
      it "aliases #bytes with #b" do
        expect(long.b).to eq(long.bytes)
      end
      it "aliases #chars with #c" do
        expect(long.c).to eq(long.chars)
      end
      it "aliases #str with #s" do
        expect(long.s).to eq(long.str)
      end
      it "aliases #hex with #h" do
        expect(long.h).to eq(long.hex)
      end
      it "aliases str with to_s" do
        expect(long.to_s).to eq(long.str)
      end
    end
    
  end # conversion

  context "==" do
    it "can compare to buffers" do
      expect(short == short).to be_truthy
    end
    it "can be compared with ints" do
      expect(short == 1).to be_truthy
    end
    it "can be compared with strings" do
      expect(long == "The House").to be_truthy
    end
    it "can be compared with a hex string" do
      expect(mid == "AABB").to be_truthy
    end
    it "can be compared with a hex int" do
      expect(short == 0x1).to be_truthy
    end
    it "can be compared with a multi digit hex int" do
      expect(mid == 0xaABb).to be_truthy
    end
  end
  context "enumerable" do
  end
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
  context "#xor_all_with as shorthand for xor(val,expand = true)" 
  
end


