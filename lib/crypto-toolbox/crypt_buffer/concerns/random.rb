module CryptBufferConcern
  module Random
    # This module provides an interface to generate
    # a CryptBuffer with n bytes of random Integer
    # between 1 and 256
    # This is required for generating pseudo keys

    def self.included(base)
      base.extend(ClassMethods)
    end
    
    module ClassMethods
      def random(n,seed: Time.now.to_i)
        bytes = generate_bytes(n,seed)
        CryptBuffer(bytes)
      end


      private
      def generate_bytes(n,seed)
        prg = ::Random.new(seed)

        ::Array.new(n.to_i) { prg.rand 256 }
      end
    end

  end
end
