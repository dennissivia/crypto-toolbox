module Utils
  class EcbDetector
    def detect(ciphers)
      result = ciphers.map.with_index{|c,i| detect_ecb_entry(c,i) }
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

    def detect_ecb_entry(ciphertext,index)
      if duplicate_chunk?(ciphertext.chunks_of(16))
        [index,ciphertext]
      else
        []
      end
    end
    
  end
end
