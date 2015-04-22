module CryptBufferConcern
  module Comparable
    def ==(other)
      bytes == CryptBuffer(other).bytes
    end
  end
end
