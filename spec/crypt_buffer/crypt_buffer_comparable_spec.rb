require 'spec_helper'

describe CryptBuffer do
  let(:short){ CryptBuffer(1)    } 
  let(:mid)  { CryptBuffer("0xaAbB") }
  let(:long) { CryptBuffer("The House")  }
  let(:empty){ CryptBuffer([])   }
  
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
end




