require 'spec_helper'

RSpec.describe Utils::EcbOracle,wip: false do
  
  context "input encryption" do
    let(:plaintext)  { "1-2-3-4-5-6-7-8-9: Mary had a little lamb, His fleece was white as snow, And everywhere that Mary went, The lamb was sure to go."  }
    let(:subject)    { Utils::EcbOracle.new(prepend: true, append: true) }
    it "encrypts the input (without any key given)" do
      expect{
        subject.encipher(plaintext)
      }.to_not raise_error
    end

    it "gives access to a backdoor check of the encryption mode" do
      modes=[:ecb,:cbc]
      _ = subject.encipher(plaintext)
      
      expect(modes).to include(subject.mode)
    end

    it "pads the message with at least 10 bytes" do
      ciphertext = subject.encipher(plaintext)
      expect(ciphertext.length >= plaintext.length + 10).to be_truthy
    end
    it "pads the message with at most 20 bytes" do
      ciphertext = subject.encipher(plaintext)

      # maximum + maximum passible padding size
      expect(ciphertext.length <= plaintext.length + 20 + 15).to be_truthy
    end
  end
  
end
