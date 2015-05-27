require 'spec_helper'


RSpec.describe Matasano::Solver do

  context "challange9" do
    let(:input)  { "YELLOW SUBMARINE" }
    let(:output) { "YELLOW SUBMARINE\x04\x04\x04\x04" }
    
    it "is solved" do
      expect(subject.solve9(input)).to eq(output)
    end
  end
  
  context "challange10" do
    let(:key)    { "YELLOW SUBMARINE" }
    let(:iv)     { (1..16).map{|_| 0.chr }.to_a.join }
    let(:input)  { File.read("challange-input/matasano/set2-challange10.txt")}
    let(:result) { "I'm back and I'm ringin' the bell" }

    
    it "solves challange 10" do
      expect(subject.solve10(key,input,iv)).to include(result)
    end
  end

  context "challange11" do
    let(:plaintext)  { "1-2-3-4-5-6-7-8-_ _ _ _ _ _ _ _ 1-2-3-4-5-6-7-8-: Mary had a little lamb, His fleece was white as snow, And everywhere that Mary"  }
    let(:oracle)     { Utils::EcbOracle.new   }
    let(:detector)   { Utils::EcbDetector.new }

    context "can always detect ECB mode if two 16 byte blocks are identical" do
      
      (1..50).each do |i|
        it "works on iteration #{i} " do
          ciphertext  = oracle.encipher(plaintext)
          mode        = oracle.mode
          # expect true if ecb, otherwise false
          expectation = (mode == :ecb)
          
          expect(detector.is_ecb?(ciphertext)).to eq(expectation)
        end
      end
    end
  end
  
  context "challange12",cpu_burner: true do
    let(:suffix) {
      Base64.decode64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    }
    let(:plaintext) { suffix }
    let(:key)       { "my-secret-key" }
    let(:mode)      { :ecb            }
    let(:oracle)    { Utils::EcbOracle.new(static_key: key,static_mode: mode,static_suffix: suffix,prepend: false, append: true) }

    it "solves the challange" do
      result = subject.solve12(oracle)

      expect(result).to eq(plaintext)
    end
  end

  context "challange13" do
    let(:key)  { "super-secret" }
    
    it "solves the challange" do
      result = subject.solve13(key)

      expect(result[:role]).to eq("admin")
    end
  end

  context "challange14",cpu_burner: true do
    let(:suffix) {
      Base64.decode64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    }
    # use the same random prefix for all the encryptions
    let(:prefix)    { SecureRandom.random_bytes(rand(16)) }
    let(:key)       { "my-secret-key" }
    let(:mode)      { :ecb            }
    let(:plaintext) { suffix }
    let(:oracle)    { Utils::EcbOracle.new(static_key: key,static_mode: mode,static_prefix: prefix,static_suffix: suffix,prepend: true, append: true) }

    it "solves the challange" do
      plaintext = subject.solve14(oracle)

      expect(plaintext).to eq(plaintext)
    end
  end

  context "challange15" do
    let(:padded)   { "ICE ICE BABY\x04\x04\x04\x04" }
    let(:unpadded) { "ICE ICE BABY" }

    it "strips existing padding" do
      expect(subject.solve15(padded)).to eq(unpadded)
    end
    
    it "raises an error on missing paddings" do
      expect{
        subject.solve15(unpadded)
      }.to raise_error
    end
    
  end
  
  
end



