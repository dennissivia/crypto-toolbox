require 'spec_helper'


RSpec.describe CryptoChallanges::Solver do

  context "#solve1" do
    let(:input)  { "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d" }
    let(:output) { "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" }
    it "solves the challange" do
      expect(subject.solve1(input)).to eq(output)
    end
  end
  
  context "solve2" do
    let(:c1)     { "1c0111001f010100061a024b53535009181c" }
    let(:c2)     { "686974207468652062756c6c277320657965" }
    let(:output) { "746865206b696420646f6e277420706c6179" }
    it "solves the challange" do
      expect(subject.solve2(c1,c2)).to eq(output)
    end
  end
  
  context "solve3" do
    let(:input) { "746865206b696420646f6e277420706c6179" }
    it "solves the challange" do
      expect(subject.solve3(input)).to eq("the kid don't play")
    end
  end

  context "solve4" do
    let(:input) { File.read("challanges/cryptopals/set1-challange4.txt").split("\n") }
    it "solves the challange" do
      expect(subject.solve4(input)).to eq("Now that the party is jumping\n")
    end
  end

  context "solve5" do
    let(:key)       { "ICE" }
    let(:input)     { "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal" }
    let(:output)    { "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".upcase }

    
    it "solves the challange " do
      expect(subject.solve5(input,key)).to eq(output)
    end
  end

  context "challange6"  do
    let(:input) { File.read("challanges/cryptopals/set1-challange6.txt") }

    it "solves the challange" do
      expect(subject.solve6(input).first.str).to include("I'm back and I'm ringin' the bell")
    end
  end
  
  context "challange7",wip: false do
    let(:key)   { "YELLOW SUBMARINE" }
    let(:input) { File.read("challanges/cryptopals/set1-challange6.txt") }
    let(:plain) { "foobar" }
    
    it "solves the challange" do
      skip "nyd"
      expect(subject.solve7(input,key)).to include(plain)
    end
  end
end
