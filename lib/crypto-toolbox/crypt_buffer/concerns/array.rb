module CryptBufferConcern
  module Array
    def +(other)
      # make sure the input is a cryptbuffer
      # Thus we support cryptbuffers and byte arrays
      CryptBuffer(bytes + CryptBuffer(other).bytes)
    end

    def shift(n = 1)
      CryptBuffer(bytes.shift(n))
    end

    def unshift(anything)
      CryptBuffer(bytes.unshift(anything))
    end

    def first(n = 1 )
      CryptBuffer(bytes.first(n))
    end
    
    def last(n = 1)
      CryptBuffer(bytes.last(n))
    end

    def [](anything)
      CryptBuffer(bytes[anything])
    end

  end
end
