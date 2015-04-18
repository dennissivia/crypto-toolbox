module CryptBufferConcern
  module ByteExpander
    private
    def expand_bytes(input,total)
      if input.length >= total
        input
      else
        n = total / input.length
        rest = total % input.length
        
        # expand the input to the full length of the internal data
        (input * n) + input[0,rest]
      end
    end
  end
end
