require 'rubygems'
require 'pry'
require 'pp'
require 'aes'

class CryptBuffer
  attr_accessor :bytes

  include Enumerable

  def initialize(input)
    @bytes = bytes_from_any(input)
  end

  def each(&block)
    @bytes.each(&block)
  end

  alias_method :b, :bytes

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

  def modulus(mod)
    real_mod = sanitize_modulus(mod)
    CryptBuffer( bytes.map{|b| b % real_mod } )
  end


  def mod_sub(n,mod: 256)
  end
  def sub(n)
    
  end
  def add(n, mod: 256, offset: 0)
    real_mod = [256,mod].min

    tmp = bytes.map do |b|
      val = (b + n) % real_mod
      val > offset ? val : val+offset
    end
    CryptBuffer(tmp)
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

  def pp
    puts pretty_hexstr
  end

  def xor_space
    xor(0x20,expand_input: true)
  end

  def ==(other)
    bytes == bytes_from_any(other)
  end

  def to_s
    str
  end

  private
  def sanitize_modulus(mod)
    (mod > 0) ? mod : 256
  end
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

  def normalize_hex(str)
    tmp = (str.length == 1) ? "0#{str}" : "#{str}"
    tmp.gsub(/(^0x|\s)/,"").upcase
  end

  def strip_hex_prefix(hex)
    raise "remove 0x from hexinput"
  end


  def xor_bytes(byt)
    len = [self.bytes.size,byt.size].min
    result = self.bytes[0...len].map.with_index{|b,i| b ^ byt[i] } + self.bytes[len,self.bytes.length - len]
    CryptBuffer.new(result)
  end

  def xor_hex(hex)
    x = hex2bytes(hex)
    xor_bytes(x)
  end

  def hex2bytes(hexstr)
    hexstr.scan(/../).map{|h| h.to_i(16) }
  end

  def str2bytes(str)
    str.bytes.to_a
  end

  def bytes2hex(bytes)
    bytes.map{|b| b.to_s(16)}.map{|hs| hs.length == 1 ? "0#{hs}" : hs  }.join
  end

  def pretty_hexstr
    str = h.scan(/.{2}/).to_a.join(" ")
   "0x#{h.upcase} (#{str.upcase})"
  end
end

def CryptBuffer(input)
  CryptBuffer.new(input)
end
