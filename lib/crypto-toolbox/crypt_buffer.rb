require 'aes'
require 'openssl'
require 'forwardable'

module CryptBufferAspect
  module Comparable
    def ==(other)
      bytes == bytes_from_any(other)
    end

  end

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
  
  module Convertable
    def hex
      bytes2hex(bytes).upcase
    end
    
    alias_method :h, :hex
    
    def chars
      map{|b| b.to_i.chr}
    end
    alias_method :c, :chars
    
    def str
      chars.join
    end
    alias_method :s, :str

    def bits
      map{|b| "%08d" % b.to_s(2) }
    end

    def to_s
      str
    end
    private
    def bytes2hex(bytes)
      bytes.map{|b| b.to_s(16)}.map{|hs| hs.length == 1 ? "0#{hs}" : hs  }.join
    end
  end

  module Xorable
    
    def xor_at(input,pos)
      return self if input.nil? || (pos.abs > length)
      
      case input
      when Array
        # map our current data to xor all inputs with the given bytepos.
        # all other bytes are kept as they were
        tmp = bytes.map.with_index{|b,i| i == pos ? xor_multiple(b,input) : b }
        CryptBuffer(tmp)
      else
        tmp = bytes
        tmp[pos] = tmp[pos] ^ input
        CryptBuffer(tmp)
      end 
    end
    
    def xor(input,expand_input: false)
      if expand_input
        xor_all_with(input)
      else
        xor_bytes(bytes_from_any(input))
      end
    end

    def xor_all_with(input)
      expanded = expand_bytes(bytes_from_any(input),self.bytes.length)
      xor_bytes(expanded)
    end


    def xor_space
      xor(0x20,expand_input: true)
    end
    private
    
    def xor_bytes(byt)
      len = [self.bytes.size,byt.size].min
      result = self.bytes[0...len].map.with_index{|b,i| b ^ byt[i] } + self.bytes[len,self.bytes.length - len]
      self.class.new(result)
    end

    def xor_hex(hex)
      x = hex2bytes(hex)
      xor_bytes(x)
    end

  end

  module ByteManipulation
    
    def modulus(mod)
      real_mod = sanitize_modulus(mod)
      CryptBuffer( bytes.map{|b| b % real_mod } )
    end

    def mod_sub(n,mod: 256)
      tmp = bytes.map do |byte|
        val = byte.to_bn.mod_sub(n,mod).to_i
      end
      CryptBuffer(tmp)
    end

    def sub(n)
      CryptBuffer( bytes.map{|byte| byte -n } )
    end
    
    def add(n, mod: 256, offset: 0)
      real_mod = [256,mod].min

      tmp = bytes.map do |b|
        val = (b + n) % real_mod
        val >= offset ? val : val+offset
      end
      CryptBuffer(tmp)
    end
  end


  module PrettyPrint
    def pp
      puts pretty_hexstr
    end
    
    private
    def pretty_hexstr
      str = h.scan(/.{2}/).to_a.join(" ")
      "0x#{h.upcase} (#{str.upcase})"
    end
  end
end



class CryptBuffer
  class OutOfRangeError < RuntimeError; end


  include CryptBufferAspect::Convertable
  include CryptBufferAspect::Comparable
  include CryptBufferAspect::Xorable
  include CryptBufferAspect::ByteManipulation
  include CryptBufferAspect::PrettyPrint
  include CryptBufferAspect::ByteExpander
  
  extend Forwardable
  def_delegators :@bytes, :[], :empty?,:include?, :length


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

  include Enumerable
  def each(&block)
    @bytes.each(&block)
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
  def sanitize_modulus(mod)
    (mod > 0) ? mod : 256
  end

  def xor_multiple(byte,bytes)
    ([byte] + bytes).reduce(:^)
  end
  def bytes_from_any(input)
    case input
      when Array
        input
      when String
        if input.match(/^0x[0-9a-fA-F]+$/).nil?
          str2bytes(input)
        else
          hex2bytes(normalize_hex(input))
        end
      when CryptBuffer
        input.b
      when Fixnum
        # integers as strings dont have a 0x prefix
        if input.to_s(16).match(/^[0-9a-fA-F]+$/)
          # assume 0x prefixed integer
          hex2bytes(normalize_hex(input.to_s(16)))
        else
          # regular number
          [input].pack('C*').bytes
        end
      else
        raise "Unsupported input: #{input.inspect} of class #{input.class}"
    end
  end

  def self.pad_hex_char(str)
    (str.length == 1) ? "0#{str}" : "#{str}"
  end
  def normalize_hex(str)
    tmp = self.class.pad_hex_char(str)
    tmp.gsub(/(^0x|\s)/,"").upcase
  end

  def strip_hex_prefix(hex)
    raise "remove 0x from hexinput"
  end

  def hex2bytes(hexstr)
    hexstr.scan(/../).map{|h| h.to_i(16) }
  end

  def str2bytes(str)
    str.bytes.to_a
  end


end

def CryptBuffer(input)
  CryptBuffer.new(input)
end
