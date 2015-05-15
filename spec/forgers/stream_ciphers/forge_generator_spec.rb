require 'spec_helper'

RSpec.describe Forgers::StreamCipher::ForgeGenerator do
  let(:m)  { "attack at dawn" }
  let(:m_) { "attack at dusk" }
  let(:c)  { "09e1c5f70a65ac519458e7e53f36" }
  let(:c_) { "09E1C5F70A65AC519458E7F13B33" }
  

  context "#forge" do
    context "full plaintext known" do
      it "creates a valid forge" do
        expect(subject.forge(c,m,m_).hex).to eq(c_)
      end
    end

    context "parital knowledge (beginning of the plaintext)" do
      let(:full_message) { "Receiver: bob<...This the rest of the unknown message>" }
      let(:m)   { "Receiver: bob" }
      let(:m_)  { "Receiver: sam" }
      let(:key) { "secretkey" }
      let(:c)   { CryptBuffer(full_message).xor(key,expand_input: true) }
      let(:expected)  { CryptBuffer.from_hex("210000170C020E17435316021F595A454B2D1B0C1052111C0E450B161617520A124B11111645161C0E1A0412175308060116150C0047") }
      
      before(:each) do
        @result = subject.forge(c.hex,m,m_)
      end
      
      it "forges correctly" do
        expect(@result.hex).to eq(expected.hex)
      end
      it "creates c' with the same length as c" do
        expect(@result.length).to eq(expected.length)
      end
      it "only differs in 3 places (or 9 bits)" do
        expect(c.hdist(@result)).to eq(9)
      end
    end
  end
  
  context "partial knownledge (somewhere in the plaintext)ip" do
      let(:full_message) { "Receiver: bob<...This the rest of the unknown message>" }
      let(:m)   { "__________bob" }
      let(:m_)  { "__________sam" }
      let(:key) { "secretkey" }
      let(:c)   { CryptBuffer(full_message).xor(key,expand_input: true) }
      let(:expected)  { CryptBuffer.from_hex("210000170C020E17435316021F595A454B2D1B0C1052111C0E450B161617520A124B11111645161C0E1A0412175308060116150C0047") }
      
      before(:each) do
        @result = subject.forge(c.hex,m,m_)
      end
      
      it "forges correctly" do
        expect(@result.hex).to eq(expected.hex)
      end
      it "creates c' with the same length as c" do
        expect(@result.length).to eq(expected.length)
      end
      it "only differs in 3 places (or 9 bits)" do
        expect(c.hdist(@result)).to eq(9)
      end
  end
  
  context ".forge" do
    it "provides a class level interface" do
      expect(subject.class.forge(c,m,m_).hex).to eq(subject.forge(c,m,m_).hex)
    end
    
  end
end


