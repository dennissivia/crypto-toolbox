require 'spec_helper'

RSpec.describe CryptBuffer do
  context ".random(n)",:wip => true do
    let(:empty) { CryptBuffer([]) }
    it "returns a CryptBuffer" do
      expect(CryptBuffer.random(10).kind_of?(CryptBuffer)).to be_truthy
    end
    it "creates a Buffer of length n" do
      expect(CryptBuffer.random(10).length).to eq(10)
    end
    it "returns an empty buffer on n:nil" do
      expect(CryptBuffer.random(nil)).to eq(empty)
    end
    it "returns an empty buffer on n:0" do
      expect(CryptBuffer.random(0)).to eq(empty)
    end
    it "returns works for n:0" do
      expect(CryptBuffer.random(1).length).to eq(1)
    end
    it "uses modulus 256" do
      expect(CryptBuffer.random(1000).bytes.all?{|b| b < 256} ).to be_truthy
    end
    it "provides access to the prng seed" do
      expect(CryptBuffer.random(5,seed: 12345).bytes).to eq([226, 229, 29, 129, 164])
    end
  end

end
