require_relative './../lib/crypt_buffer.rb'

describe CryptBuffer do
  context "#bytes" do
    it "gives access to the byte repreesntation" do
      expect(CryptBuffer.new(0x0F).bytes).to eq([15])
    end
  end
  context "#initialize" do
    let(:value){ 32 }

    [0x20,"0x20"," ",32].each do |input|
      it "should accept a #{input} of type #{input.class}" do
        expect{CryptBuffer.new(input)}.to_not raise_error
      end
      it "converts input of type #{input.class} properly" do
        expect(CryptBuffer.new(input).bytes).to eq([value])
      end
    end
  end
  context "CryptBuffer()" do
  end
end
