module Utils
  class HammingDistanceFilter
    def shortest_distance_entries(buffer,result_entries: 4,samples: 4)
      offset = 2
      distances = ((0+offset)..64).map do |keysize|
        # take the first 4 blocks of keysize length, generate all combinations (6),
        # map than to normalized hamming distance and take mean
        buffer.chunks_of(keysize)[0,samples].combination(2).map{|a,b| a.hdist(b,normalize: true)}.reduce(&:+) / 6.0
      end
      # get the min distance, find its index, convert the keylen
      distances.min(result_entries).map{|m| distances.index(m)}.map{|i| i + offset }.uniq
    end
  end
end
  
