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
      expect(mid == "0xAABB").to be_truthy
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
  end
  
  context "nth_bits" do
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
  context "#length" do
    it "responds to length with the amout of bytes" do
      expect(CryptBuffer("0xFFeeCC01").length).to eq(4)
    end
    it "support empty data" do
      expect(CryptBuffer([]).length).to eq(0)
    end
  end
  context "delegates #empty?" do
    it "delegates empty? for none-empty data" do
      expect(CryptBuffer("0xFFeeCC01").empty?).to be_falsy
    end
    it "delegates empty? for empty data" do
      expect(CryptBuffer([]).empty?).to be_truthy
    end
  end
  context "#[]" do
    let(:buf){ CryptBuffer("0x050607") }
    it "delegates []" do
      expect(buf[0]).to eq(5)
      expect(buf[1]).to eq(6)
      expect(buf[2]).to eq(7)
    end
    it "works for invalid negative indices" do
      expect(buf[-1]).to eq(7)
    end
    it "works for too high indices" do
      expect(buf[9]).to eq(nil)
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
  
  context "chunks_of(N) split buffer into parts of size N" do
    let(:buf) { CryptBuffer([1,1,1,2,2,2,3,3,3]) }

    context "exact multiples of N" do
      let(:part1) { CryptBuffer([1,1,1]) }
      let(:part2) { CryptBuffer([2,2,2]) }
      let(:part3) { CryptBuffer([3,3,3]) }
    
      it "split a chunks without rest when N is a multiple of the bytes" do
        expect(buf.chunks_of(3)).to eq([part1,part2,part3])
      end
    end
    context "not exact multiples of N" do
      let(:part1) { CryptBuffer([1,1,1,2]) }
      let(:part2) { CryptBuffer([2,2,3,3]) }
      let(:part3) { CryptBuffer([3]) }
      it "works with byte amounts that are not a multiple of N" do
        expect(buf.chunks_of(4)).to eq([part1,part2,part3])
      end
    end
  end
end




