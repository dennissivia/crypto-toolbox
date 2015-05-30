
module Matasano
  module Sets
    module Set3
      def solve17(oracle)
        ciphertext = oracle.sample_ciphertext
        result     = Analyzers::PaddingOracle::Analyzer.new(oracle).analyze(ciphertext)
      end
    end
  end
end
