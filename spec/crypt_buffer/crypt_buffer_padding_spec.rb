require 'spec_helper'

describe CryptBuffer do
  context "padding concern" do
    let(:padded)     { CryptBuffer([1,2,3,4,5,6,7,8,5,5,5,5,5]) }
    let(:stripped)   { CryptBuffer([1,2,3,4,5,6,7,8]) }
    let(:not_padded) { CryptBuffer([1,2,3,4,5,6,7,8,9,5,5,5,5]) }
    let(:empty)      { CryptBuffer([]) }
    
    context "#padding" do

      it "returns the the included padding" do
        expect(padded.padding).to eq(CryptBuffer([5,5,5,5,5]))
      end
      
      it "returns [] if no pkcs7 padding is present" do
        expect(not_padded.padding).to eq(CryptBuffer([]))
      end
      it "returns [] if the buffer is empty" do
        expect(empty.padding).to eq(CryptBuffer([]))
      end
    end
    context "#strip_padding" do
      it "strips an existing padding from a buffer" do
        expect(padded.strip_padding).to eq(stripped)
      end
      it "returns the original object if no padding is found" do
        expect(not_padded.strip_padding).to eq(not_padded)
      end
      it "returns the original object if no the buffer is empty" do
        expect(empty.strip_padding).to eq(empty)
      end
    end
    
    context "#pad(n)" do
      let(:pad_replaced) { CryptBuffer([1,2,3,4,5,6,7,8,6,6,6,6,6,6]) }
      let(:double_padded){ CryptBuffer([1,2,3,4,5,6,7,8,5,5,5,5,5,6,6,6,6,6,6]) }
      let(:pad_only){ CryptBuffer([6,6,6,6,6,6]) }
      it "adds an n byte padding" do
        expect(stripped.pad(5)).to eq(padded)
      end
      it "replaces an existing padding if replace: true is given" do
        expect(padded.pad(6,replace: true)).to eq(pad_replaced)
      end
      it "defaults to replace:true" do
        expect(padded.pad(6)).to eq(pad_replaced)
      end
      it "does not replace the existing padding if replace: is false" do
        expect(padded.pad(6,replace: false)).to eq(double_padded)
      end
      it "works on empty buffers" do
        expect(empty.pad(6)).to eq(pad_only)
      end
    end
  end
end




