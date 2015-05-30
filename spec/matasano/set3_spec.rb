require 'spec_helper'


RSpec.describe Matasano::Solver do

  context "challange17" do
    it "is solved" do
      oracle = CryptoToolbox::Oracles::PaddingOracle::MemoryOracle.new
      expect(subject.solve17(oracle)).to eq(oracle.secret_plaintext)
    end
  end
end
