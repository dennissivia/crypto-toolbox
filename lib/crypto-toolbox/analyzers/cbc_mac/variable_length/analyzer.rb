require 'crypto-toolbox/analyzers/cbc_mac/variable_length/oracles/tcp.rb'

module Analyzers
  module CbcMac
    module VariableLength
      
      class Analyzer
        # This class implements an attack on CBC-MAC with variable length. 
        # This issue is known for a long time and thus should be avoided by any implementation.
        # However this code shows how to forge a tag in this mode and can be seen das a PoC.
        #
        #
        # Thanks to Matthew Green for this great article about the potential implementation problems
        # of CBC-MAC: http://blog.cryptographyengineering.com/2013/02/why-i-hate-cbc-mac.html
        #
        # This class has the VL (variable length) suffix it its name
        # to make100% clear that this attack works only on this condition
        def initialize(oracle_class = ::Analyzers::CbcMac::VariableLength::Oracles::Tcp,block_length=32)
          @oracle = oracle_class.new
        end
        # NOTE: handle too short messages properly
        
        def analyze(target_message)
          @oracle.connect

          # split the target message into chunks of size N (e.g. 32)
          target_bufs = CryptBuffer(target_message).chunks_of(32)

          # receive the valid mac for the first chunk of the target message
          tag1 = CryptBuffer(@oracle.mac(target_bufs[0]))

          attack_message = assemble_malicious_message(target_bufs,tag1)
          forged_tag = @oracle.mac(attack_message)

          ret = @oracle.verify(target_message, forged_tag)

          report_result(ret,forged_tag)
          
          @oracle.disconnect          
        end
        
        private
          # Create a message that consists of
          # 1) the first n byte of the second message xored with tag t from the first message
          # 2) the remaining blocks of the second message
          # short:  t''  = (m'_0  xor t ) ||m'_1 ||...||m'_n]          
        def assemble_malicious_message(target_bufs,tag1)

          # split the second chunk into blocks of the size of the tag
          m2_blocks = target_bufs[1].chunks_of(tag1.length)

          CryptBuffer((m2_blocks[0].xor(tag1)).bytes + m2_blocks[1].bytes)
        end
        
        def report_result(ret,tag)
          if forge_successfull?(ret)
            puts "[Success] Resulting tag is: #{CryptBuffer(tag).pretty_hexstring}"
          else
            puts "[Failure] Message verification failed."
          end
        end
        
        def forge_successfull?(retval)
          retval == 1
        end
        
      end
      

      
    end
  end
end
