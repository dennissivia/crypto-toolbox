require 'spec_helper'

RSpec.describe CryptBufferConcern::TypeExtension do

  context "#to_crypt_buffer" do
    let(:hexstring) { "0xffeeddcc" }
    let(:string)    { "This is my string" }
    let(:fixnum)    { 250 }
    let(:array)     { [2,5,7,10,200] }
    
    it "is supported by String" do
      expect(hexstring.to_crypt_buffer).to eq(CryptBuffer(hexstring))
    end

    it "is supported by Array" do
      expect(array.to_crypt_buffer).to eq(CryptBuffer(array))
    end

    it "is supported by fixnum" do
      expect(fixnum.to_crypt_buffer).to eq(CryptBuffer(fixnum))
    end

    it "is suppored by hex-strings" do
      expect(hexstring.to_crypt_buffer).to eq(CryptBuffer(hexstring))
    end
    
  end
end
