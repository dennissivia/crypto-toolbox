require 'aes'
require 'openssl'
require 'forwardable'


require 'crypto-toolbox/crypt_buffer/concerns/arithmetic.rb'
require 'crypto-toolbox/crypt_buffer/concerns/array.rb'
require 'crypto-toolbox/crypt_buffer/concerns/byte_expander.rb'
require 'crypto-toolbox/crypt_buffer/concerns/comparable.rb'
require 'crypto-toolbox/crypt_buffer/concerns/convertable.rb'
require 'crypto-toolbox/crypt_buffer/concerns/padding.rb'
require 'crypto-toolbox/crypt_buffer/concerns/pretty_print.rb'
require 'crypto-toolbox/crypt_buffer/concerns/random.rb'
require 'crypto-toolbox/crypt_buffer/concerns/xor.rb'

class CryptBuffer
  class OutOfRangeError < RuntimeError; end
  attr_accessor :bytes
  alias_method :b, :bytes

  
  include Enumerable
  extend Forwardable
  def_delegators :@bytes,:empty?,:include?, :length, :each, :|, :&

  # NOTE
  # we need to include all the extensions after the regular delegate
  # otherwise we are not able to overwrite methods like first/last
  # which would result in the inability of casting the result to a
  # new cryptbuffer instance, thus leaving the return value an array
  include CryptBufferConcern::Arithmetic
  include CryptBufferConcern::Array
  include CryptBufferConcern::ByteExpander
  include CryptBufferConcern::Convertable
  include CryptBufferConcern::Comparable
  include CryptBufferConcern::Padding
  include CryptBufferConcern::PrettyPrint
  include CryptBufferConcern::Random
  include CryptBufferConcern::Xor


  
  def initialize(byte_array)
    @bytes = byte_array
  end

  # Make sure input strings are always interpreted as hex strings
  # This is especially useful for unknown or uncertain inputs like
  # strings with or without leading 0x
  def self.from_hex(input)
    CryptBufferInputConverter.new.from_hex(input)
  end

  def self.from_base64(input)
    CryptBufferInputConverter.new.from_base64(input)
  end

  def nth_bytes(n,offset: 0)
    return CryptBuffer([]) if n.nil? || n < 1

    CryptBuffer((0+offset).step(length,n).map{|i| bytes[i] }.compact)
  end
  

  # Returns an array of the nth least sigificant by bit of each byte
  def nth_bits(n)
    raise OutOfRangeError if n < 0
    raise OutOfRangeError if n > 7
    
    bits.map{|b| b.reverse[n].to_i }
  end
  
  def chunks_of(n)
    self.bytes.each_slice(n).map{|chunk| CryptBuffer(chunk) }
  end
end


