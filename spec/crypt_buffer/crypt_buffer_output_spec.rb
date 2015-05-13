require 'spec_helper'

describe CryptBuffer do
  let(:short){ CryptBuffer(1)    } 
  let(:mid)  { CryptBuffer("0xaAbB") }
  let(:long) { CryptBuffer("The House")  }
  let(:empty){ CryptBuffer([])   }

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
    context "#base64" do
      it "encodes every byte in base64" do
        expect(long.base64).to eq("VGhlIEhvdXNl")
      end
      it "handles empty buffers" do
        expect(empty.str).to eq("")
      end
    end

    context "#str" do
      it "returns a string of the internal state" do
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
  end
end

