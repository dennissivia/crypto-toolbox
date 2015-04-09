require 'spec_helper'

RSpec.describe Ciphers::Caesar do
  context "#encode" do
    it "handles A as 0 shift" do
      expect(subject.encode("AAAA","A")).to eq("AAAA")
    end
    it "handles B as 1 shift" do
      expect(subject.encode("AAAA","B")).to eq("BBBB")
    end
    it "wraps from Z to A" do
      expect(subject.encode("ZZZZ","B")).to eq("AAAA")
    end
  end

  context "#decode" do
    it "handles A as 0 shift" do
      expect(subject.decode("AAAA","A")).to eq("AAAA")
    end
    it "handles B as 1 shift" do
      expect(subject.decode("BBBB","B")).to eq("AAAA")
    end
    it "wraps from Z to A" do
      expect(subject.decode("AAAA","B")).to eq("ZZZZ")
    end
  end

  context "formal correctness (invertability)" do
    ("A".."Z").each do |char|
      it "D(E(m)) == m for #{char} as shift" do
        input=("A".."Z").to_a.join("")
        enc = subject.encode(input,"G")
        dec = subject.decode(enc,"G")
      
        expect(dec).to eq(input)
      end
    end
  end

  context "class methods" do
    it "self.encode" do
      expect(Ciphers::Caesar.encode("AAAA","B")).to eq("BBBB")
    end
    it "self.decode" do
      expect(Ciphers::Caesar.decode("AAAA","C")).to eq("YYYY")
    end
  end

  
end
