module CryptoToolbox
  module Oracles
    module PaddingOracle
      class HttpOracle
        def initialize
          require 'net/http'
          @domain   = "crypto-class.appspot.com"
          @uri_base = "/po?er="
          @port     = 80
        end
        def connect
          true
        end
        def disconnect
          true
        end
        def valid_padding?(input,block_amount)

          uri = @uri_base + input.hex

          Net::HTTP.start(@domain,@port) do |http|
            res   = http.request(Net::HTTP::Get.new(uri))
            code  = res.code.to_i
            sleep 0.001
            
            #   -> howto check this ? (block_index == 3 && pad_index == 9 && code == 200 )
            (code == 404 || code == 200)
          end
        end
        
      end
    end
  end
end


