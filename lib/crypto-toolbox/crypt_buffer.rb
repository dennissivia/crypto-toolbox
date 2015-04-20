require 'aes'
require 'openssl'
require 'forwardable'

require 'crypto-toolbox/crypt_buffer/concerns/arithmetic.rb'
require 'crypto-toolbox/crypt_buffer/concerns/byte_expander.rb'
require 'crypto-toolbox/crypt_buffer/concerns/comparable.rb'
require 'crypto-toolbox/crypt_buffer/concerns/convertable.rb'
require 'crypto-toolbox/crypt_buffer/concerns/padding.rb'
require 'crypto-toolbox/crypt_buffer/concerns/pretty_print.rb'
require 'crypto-toolbox/crypt_buffer/concerns/random.rb'
require 'crypto-toolbox/crypt_buffer/concerns/xor.rb'

class CryptBuffer
  class OutOfRangeError < RuntimeError; end
  
  include CryptBufferConcern::Arithmetic
  include CryptBufferConcern::ByteExpander
  include CryptBufferConcern::Convertable
  include CryptBufferConcern::Comparable
  include CryptBufferConcern::Padding
  include CryptBufferConcern::PrettyPrint
  include CryptBufferConcern::Random
  include CryptBufferConcern::Xor

  
  include Enumerable
  extend Forwardable
  def_delegators :@bytes, :[], :empty?,:include?, :each, :length

  
  attr_accessor :bytes
  alias_method :b, :bytes



  
  def initialize(input)
    @bytes = bytes_from_any(input)
  end

  # Make sure input strings are always interpreted as hex strings
  # This is especially useful for unknown or uncertain inputs like
  # strings with or without leading 0x
  def self.from_hex(input)
    hexstr =""
    unless input.nil?
      hexstr = (input =~ /^0x/ ? input : "0x#{pad_hex_char(input)}" )
    end
    CryptBuffer.new(hexstr)
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



  
  private
  def xor_multiple(byte,bytes)
    ([byte] + bytes).reduce(:^)
  end
  
  def bytes_from_any(input)
    case input
    when Array
      input
    when String
      str2bytes(input)
    when CryptBuffer
      input.b
    when Fixnum
      int2bytes(input)
    else
      raise "Unsupported input: #{input.inspect} of class #{input.class}"
    end
  end

  def normalize_hex(str)
    tmp = self.class.pad_hex_char(str)
    tmp.gsub(/(^0x|\s)/,"").upcase
  end
  
  def self.pad_hex_char(str)
    (str.length == 1) ? "0#{str}" : "#{str}"
  end
  
  def strip_hex_prefix(hex)
    raise "remove 0x from hexinput"
  end
  
  def int2bytes(input)
    # integers as strings dont have a 0x prefix
    if input.to_s(16).match(/^[0-9a-fA-F]+$/)
      # assume 0x prefixed integer
      hex2bytes(normalize_hex(input.to_s(16)))
    else
      # regular number
      [input].pack('C*').bytes
    end
  end
  
  def hex2bytes(hexstr)
    hexstr.scan(/../).map{|h| h.to_i(16) }
  end

  def str2bytes(str)
    if str.match(/^0x[0-9a-fA-F]+$/).nil?
      str.bytes.to_a
    else
      hex2bytes(normalize_hex(str))
    end
  end
end


def CryptBuffer(input)
  CryptBuffer.new(input)
end
