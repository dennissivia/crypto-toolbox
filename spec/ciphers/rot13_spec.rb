require 'spec_helper'

RSpec.describe Ciphers::Rot13 do

  context "real world example" do
    context "encipher" do
      it "generated the correct values for every upper case letter" do
        expect(subject.encipher("ABCDEFGHIJKLMNOPQRSTUVWXYZ")).to eq("NOPQRSTUVWXYZABCDEFGHIJKLM")
      end
      it "generated the correct values for every lower case letter" do
        expect(subject.encipher("abcdefghijklmnopqrstuvwxyz")).to eq("nopqrstuvwxyzabcdefghijklm")
      end
    end

    context "decipher" do
      it "generated the correct values for every upper case letter" do
        expect(subject.decipher("ABCDEFGHIJKLMNOPQRSTUVWXYZ")).to eq("NOPQRSTUVWXYZABCDEFGHIJKLM")
      end
      it "generated the correct values for every lower case letter" do
        expect(subject.decipher("abcdefghijklmnopqrstuvwxyz")).to eq("nopqrstuvwxyzabcdefghijklm")
      end
      it "correctly decodes a funny string" do
        string="Jul qvq gur puvpxra pebff gur ebnq? - Gb trg gb gur bgure fvqr!"
        expect(subject.decipher(string)).to eq("Why did the chicken cross the road? - To get to the other side!")
      end
    end
    context "consistency" do
      let(:string){"Why did the chicken cross the road? - To get to the other side!"}
      it "is correctly invertable ROT13d(ROT13e(x)) = x" do
        enc    = subject.encipher(string)
        dec    = subject.decipher(enc)
        expect(dec).to eq(string)
      end
      it "is invertable by itself ROT13e(ROT13e(x)) = x" do
        enc    = subject.encipher(string)
        dec    = subject.encipher(enc)
        expect(dec).to eq(string)
      end
      it "is invertable by itself ROT13d(ROT13d(x)) = x" do
        enc    = subject.decipher(string)
        dec    = subject.decipher(enc)
        expect(dec).to eq(string)
      end

      it "provides an short hand, due to equality of encipher and decipher" do
        enc    = subject.apply(string)
        dec    = subject.apply(enc)
        expect(dec).to eq(string)
      end

    end
  end
end
