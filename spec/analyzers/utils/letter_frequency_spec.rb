require 'spec_helper'

RSpec.describe Analyzers::Utils::LetterFrequency do
  
  let(:input) { "Mary had a little lamb,His fleece was white as snow,And everywhere that Mary went,The lamb was sure to go." }

  let(:chars) { {"m"=>4, "a"=>11, "r"=>5, "y"=>3, " "=>18, "h"=>6, "d"=>2, "l"=>5, "i"=>3, "t"=>8, "e"=>12, "b"=>2, "s"=>6, "f"=>1, "c"=>1, "w"=>6, "n"=>3, "o"=>3, "v"=>1, "u"=>1, "g"=>1} }

  let(:freqs) {
    {" "=>0.1765, "e"=>0.1176, "a"=>0.1078, "t"=>0.0784, "w"=>0.0588, "s"=>0.0588, "h"=>0.0588, "l"=>0.049, "r"=>0.049, "m"=>0.0392, "o"=>0.0294, "n"=>0.0294, "i"=>0.0294, "y"=>0.0294, "b"=>0.0196, "d"=>0.0196, "g"=>0.0098, "u"=>0.0098, "v"=>0.0098, "c"=>0.0098, "f"=>0.0098 }
  }
  
  context "#letter_count" do
    it "counts the chars" do
      expect(subject.letter_count(input)).to eq(chars)
    end
  end
  context "#letter_freq" do
    it "calculates the letter frequencies" do
      expect(subject.letter_freq(input)).to eq(freqs)
    end
  end
end
