require 'spec_helper'

RSpec.describe Ciphers::Caesar do
  context "#encipher" do
    it "handles A as 0 shift" do
      expect(subject.encipher("AAAA","A")).to eq("AAAA")
    end
    it "handles B as 1 shift" do
      expect(subject.encipher("AAAA","B")).to eq("BBBB")
    end
    it "wraps from Z to A" do
      expect(subject.encipher("ZZZZ","B")).to eq("AAAA")
    end
    it "preseves spaces" do
      expect(subject.encipher("    ","B")).to eq("    ")
    end
  end

  context "#decipher" do
    it "handles A as 0 shift" do
      expect(subject.decipher("AAAA","A")).to eq("AAAA")
    end
    it "handles B as 1 shift" do
      expect(subject.decipher("BBBB","B")).to eq("AAAA")
    end
    it "wraps from Z to A" do
      expect(subject.decipher("AAAA","B")).to eq("ZZZZ")
    end
    it "preserves spaces" do
      expect(subject.decipher("    ","B")).to eq("    ")
    end

  end
  context "real life examples" do
    let(:cipher){"WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ"}
    let(:plain) {"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"}
    it "enciphers correctly" do
      expect(subject.encipher(plain,"D")).to eq(cipher)
    end
  end


  context "formal correctness (invertability)" do
    ("A".."Z").each do |char|
      it "D(E(m)) == m for #{char} as shift" do
        input=("A".."Z").to_a.join("")
        enc = subject.encipher(input,"G")
        dec = subject.decipher(enc,"G")
      
        expect(dec).to eq(input)
      end
    end
  end

  context "class methods" do
    it "self.encipher" do
      expect(Ciphers::Caesar.encipher("AAAA","B")).to eq("BBBB")
    end
    it "self.decipher" do
      expect(Ciphers::Caesar.decipher("AAAA","C")).to eq("YYYY")
    end
  end

  
end
