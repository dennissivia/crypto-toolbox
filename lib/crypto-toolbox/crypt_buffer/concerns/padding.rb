module CryptBufferConcern
  module Padding
    # This module extends functionality the CryptBuffer to
    # handle PKCS7 padding.
    # It has the ability to detect, replace, add and strip a
    # padding from a CryptBuffer to return a new one without
    # mutating the existing buffer.
    #
    # The purpose is making crypto analysis of cbc and other
    # cipher modes that use pkcs7 padding easier.

    # Return any existing padding
    def padding
      last   = bytes.last
      subset = subset_padding

      if subset.all?{|e| e == last }
        self.class.new(subset)
      else
        self.class.new([])
      end
    end

    # Strip the existing padding if present
    def strip_padding
      subset = bytes
      
      if padding?
        pad = padding
        len = pad.length
        subset = bytes[0,bytes.length - len]
      end
      self.class.new(subset)
    end

    
    def padding?
      !padding.empty?
    end

    # pad an existing buffer with the given amount of bytes
    # If a padding already exists, replace: decides whether or not
    # to replace it
    def pad(n,replace: true)
      if padding? && replace
          strip_padding.pad(n)
      else
        pad = [n] * n
        return CryptBuffer(bytes + pad )
      end
    end
    
    private
    def subset_padding
      last = bytes.last
      return [] if last.nil?
      return [] if last >= length
      # e.g. 5: take from -5,  5 elems
      bytes[-1 * last, last]
    end
  end
end
