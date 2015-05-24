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

    context "can always detect ECB mode if two 16 byte blocks are identical",wip: false do
      
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
    let(:key)      { "my-secret-key" }
    let(:mode)     { :ecb            }
    let(:oracle)   { Utils::EcbOracle.new(static_key: key,static_mode: mode,static_suffix: suffix) }

    it "solves the challange" do
      plaintext = subject.solve12(oracle,suffix)

      expect(plaintext).to include("Rollin")
    end
  end

  context "challange13" do
    let(:sample_email)   { "foo@bar.com" }
    let(:sample_role)    { "guest" }
    let(:sample_uid)     { "10" }
    let(:sample_profile) { "email=foo@bar.com&uid=10&role=guest" }
    let(:sample_hash)    { { email: sample_email, uid: sample_uid, role: sample_role } }
    let(:key)            { "super-secret" }
    let(:aes)            { Ciphers::Aes.new }
    let(:ciphertext)     { aes.encipher_ecb(key,sample_profile) }
    

    it "parses a string" do
      expect(subject.parse_profile(sample_profile)).to eq(sample_hash)
    end

    it "encodes the profile" do
      expect(subject.profile_for(sample_email)).to eq(sample_profile)
    end

    it "encryption and decryption works" do
      plaintext  = aes.decipher_ecb(key,ciphertext).to_crypt_buffer.strip_padding.str
      
      expect(plaintext).to eq(sample_profile)
    end
    
    it "solves the challange" do
      result = subject.solve13(key)

      expect(result[:role]).to eq("admin")
    end

    
  end
  
end



