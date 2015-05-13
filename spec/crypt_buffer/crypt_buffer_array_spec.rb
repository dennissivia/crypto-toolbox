require 'spec_helper'

describe CryptBuffer  do
  let(:short){ CryptBuffer(1)    } 
  let(:mid)  { CryptBuffer("0xaAbB") }
  let(:long) { CryptBuffer("The House")  }
  let(:empty){ CryptBuffer([])   }
  
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
    
    it "works for too high indices",:bug => true,:issue => "nil input must be allowed due to invalid index support" do
      expect(buf[9]).to eq(nil)
    end

    it "supports range inputs" do
      expect(long[(4..8)]).to eq(CryptBuffer([72, 111, 117, 115, 101]))
    end
    it "supports [x,y]" do
      expect(long[0,3]).to eq(CryptBuffer([84,104,101]))
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
  context "enumerable methods" do
    let(:lhs) { CryptBuffer([2,2,2]) }
    let(:arr) { [3,3,3] }
    let(:rhs) { CryptBuffer([4,4,4]) }
    let(:buf) { CryptBuffer([1,2,3,4,5]) }
    
    context "#+" do
      it "supports addition with an array of bytes" do
        expect((lhs + arr).bytes).to eq([2,2,2,3,3,3])
      end
      it "supports addition with other crypt buffers" do
        expect((lhs + rhs).bytes).to eq([2,2,2,4,4,4])
      end
    end
    context "shift" do
      it "returns a CryptBuffer of the first element" do
        expect(buf.shift).to eq(CryptBuffer([1]))
      end
      it "supports an argument n for the amount of elements" do
        expect(buf.shift(3)).to eq(CryptBuffer([1,2,3]))  
      end

      it "modifies the origial buffer" do
        mybuf = buf
        expect{
          mybuf.shift(3)
        }.to change{mybuf.length}.from(5).to(2)
      end
    end

    context "#unshift" do
      it "returns a CryptBuffer including the new element" do
        expect(buf.unshift(7)).to eq(CryptBuffer([7,1,2,3,4,5]))
      end
    end

    
    context "first" do
      it "returns a buffer with the first element" do
        expect(buf.first).to eq(CryptBuffer([1]))
      end
      
      it "supoorts an argument N" do
        expect(buf.first(3)).to eq(CryptBuffer([1,2,3]))
      end
    end
    
    context "last" do
      it "returns a buffer with the first element" do
        expect(buf.last).to eq(CryptBuffer([5]))
      end
      
      it "supoorts an argument N" do
        expect(buf.last(3)).to eq(CryptBuffer([3,4,5]))
      end

    end
  end
  
  
  context "enmerable"
end
