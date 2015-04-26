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

          #target_msg = "I, the server, hereby agree that I will pay $100 to this student"
          target_bufs = CryptBuffer(target_message).chunks_of(32)

          # add to_crypt_buffer to String!
          target_tag1 = CryptBuffer(@oracle.mac(target_bufs[0].chars,target_bufs[0].length)) #.split("").map{|i| i.bytes.first }

          # NOTE  t''  = m || [ (m_1' + t ) ||m_2'||...||m_x']
          m2_blocks = target_bufs[1].chunks_of(16)
          msg2 = CryptBuffer((m2_blocks[0].xor(target_tag1)).bytes + m2_blocks[1].bytes)

          # @oracle.tag_for(msg2.chars,msg2.length)
          forge_tag = @oracle.mac(msg2.chars,msg2.length)

          # @oracle.verify(target_msg.chars, target_msg.length, forge_tag)
          ret = @oracle.verify(target_message.chars, target_message.length, forge_tag)

          
          if forge_successfull?(ret)
            puts "result is: #{CryptBuffer(forge_tag).hex}"
            puts "Message verified successfully!"
          else
            puts "Message verification failed."
          end
          @oracle.disconnect
        end
        
        private
        
        def forge_successfull?(retval)
          retval == 1
        end
        
      end
      

      
    end
  end
end
