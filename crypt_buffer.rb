require 'rubygems'
require 'pry'
require 'pp'
require 'aes'

class CryptBuffer
  attr_accessor :bytes
  def initialize(input)
    @bytes = bytes_from_any(input)
  end

  def b
    bytes
  end
  def h
    bytes2hex(bytes) 
  end
  def chars
    bytes.map{|b| b.to_i.chr}
  end
  alias_method :c, :chars
  def str
    bytes.map{|b| b.to_i.chr}.join
  end
  alias_method :s, :str
  def bits
    bytes.map{|b| b.to_s(2) }
  end
  def xor(input)
    xor_bytes(bytes_from_any(input))
  end

  def pp
    puts pretty_hexstr
  end

  def xor_space
    self.xor("0x20")
  end

private
  def bytes_from_any(input)
    case input
      when Array
        input
      when String
        hex2bytes(normalize_hex(input))
      when CryptBuffer
        input.b
      else
        raise "Unsupported input: #{input.inspect} of class #{input.class}"
    end
  end
  def normalize_hex(str)
    str.gsub(/(^0x|\s)/,"").upcase
  end
  def strip_hex_prefix(hex)
    raise "remove 0x from hexinput"
  end
  def xor_bytes(byt)
    len = [self.bytes.size,byt.size].min
    result = self.bytes[0...len].map.with_index{|b,i| b ^ byt[i] }
    CryptBuffer.new(result)
  end
  def xor_hex(hex)
    x = hex2bytes(hex)  
    xor_bytes(x)
  end
  def hex2bytes(hexstr)
    hexstr.scan(/../).map{|h| h.to_i(16) }
  end
  def bytes2hex(bytes)
    bytes.map{|b| b.to_s(16)}.map{|hs| hs.length == 1 ? "0#{hs}" : hs  }.join
  end
  def pretty_hexstr
    str = h.scan(/.{2}/).to_a.join(" ")
   "0x#{h.upcase} (#{str.upcase})"
  end
end
