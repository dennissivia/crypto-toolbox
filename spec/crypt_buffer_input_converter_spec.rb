require 'spec_helper'

describe CryptBufferInputConverter do
  let(:short){ CryptBuffer(1)    } 
  let(:mid)  { CryptBuffer("0xaAbB") }
  let(:long) { CryptBuffer("The House")  }
  let(:empty){ CryptBuffer([])   }
  
  context "#initialize" do
    let(:value){ 32 }

    [0x20,"0x20"," ",32].each do |input|
      it "should accept a #{input} of type #{input.class}" do
        expect{CryptBuffer(input)}.to_not raise_error
      end
      it "converts input of type #{input.class} properly" do
        expect(CryptBuffer(input).bytes).to eq([value])
      end
      it "allows conversion via CryptBuffer()" do
        expect(CryptBuffer(input).bytes).to eq([value])
      end
    end
  end
end

