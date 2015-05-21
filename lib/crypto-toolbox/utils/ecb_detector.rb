module Utils
  class EcbDetector

    def is_ecb?(ciphertext)
      ecb_mode?(CryptBuffer(ciphertext))
    end
    
    def detect(ciphers)
      result = ciphers.map.with_index do|c,i|
        ecb_mode?(c) ? [i,c] : []
      end
      sanitize_result(result)
    end

    private
    
    def sanitize_result(result)
      result.reject(&:empty?)
    end

    # search for any chunks whose byte-pattern occours more than once,
    # in that case the number of entries is reduced by uniq
    def duplicate_chunk?(chunks)
      chunks.map(&:bytes).uniq.length < chunks.length
    end
    
    def ecb_mode?(ciphertext)
      duplicate_chunk?(ciphertext.chunks_of(16))
    end
    
  end
end
