module CryptBufferConcern
  module Comparable
    def ==(other)
      bytes == bytes_from_any(other)
    end
  end
end
