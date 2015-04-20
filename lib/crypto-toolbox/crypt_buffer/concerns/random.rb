module CryptBufferConcern
  module Random
    
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
        if n.nil? || n.zero?
          []
        else
          prng = ::Random.new(seed)
          (1..n).map{|e| prng.rand 256 }
        end
      end
    end

  end
end
