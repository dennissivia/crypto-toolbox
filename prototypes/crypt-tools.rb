require 'rubygems'
require 'pry'
require 'pp'
require 'aes'

=begin
# convert a hex type into a string ( ascii encoded )
def hex_to_str(hex)
  hex.to_s(16).scan(/[0-9A-Fa-f]{2}/).map { |i| i.to_i.chr }.join
end
# plain text string xor
def str_xor(str,other,len)
  str[0...len].bytes.zip(other[0...len].bytes).map do |l,r|
    (l ^ r)
  end
end

=end
def alnum?(thing)
  !(thing.downcase[0].ord & (1 << 5)).zero? 
end

def hexstr_bytes(hexstr)
  hexstr.scan(/../).map{|h| h.to_i(16) }
end

def bytes_to_chars(bytes)
  bytes.map{|b| b.to_i.chr}
end
def bytes_to_str(bytes)
  bytes.map{|b| b.to_i.chr}.join
end

def bytes_to_hexstr(bytes)
  bytes.map{|b| b.to_s(16)}.map{|hs| hs.length == 1 ? "0#{hs}" : hs  }.join
end

def xor_bytes(b1,b2)
  len = [b1.size,b2.size].min
  bytes = b1[0...len].map.with_index{|b,i| b ^ b2[i] }
end

def xor_hex_strings(str1,str2)
  str1bytes = hexstr_bytes(str1)
  str2bytes = hexstr_bytes(str2)
  bytes = xor_bytes(str1bytes,str2bytes)
end

def xor_hexstr_with_str(hexstr,str)
  hexbytes = hexstr_bytes(hexstr)
  strbytes = str.bytes.to_a
  bytes = xor_bytes(hexbytes,strbytes)
end

def pretty_hexstr(hexstr)
  str = hexstr.scan(/.{2}/).to_a.join(" ")
  "0x#{hexstr.upcase} (#{str.upcase})"
end
def pp_hexstr(hexstr)
  puts pretty_hexstr(hexstr)
end

def decrypt_cbc(key,cipher)
  iv, *blocks = cipher.scan(/[0-9A-Fa-f]{32}/)
  iv_bytes = hexstr_bytes(iv)
  k_str  = bytes_to_str(hexstr_bytes(key))
  iv_str = bytes_to_str(iv_bytes)

  plain=""
  blocks.each_with_index do |block,i|
    c_bytes = hexstr_bytes(block)
    c_str = bytes_to_str(c_bytes)
  
    d_str = AES.decrypt([iv_str, c_str]  , key, {:format => :plain,:padding => false,:cipher => "AES-128-ECB",:iv => iv_str })
    d_bytes = d_str.bytes.to_a
    if i.zero?
      p_bytes = xor_bytes(d_bytes,iv_bytes)
    else
      p_bytes = xor_bytes(d_bytes,hexstr_bytes(blocks[i-1]))
    end
  
    plain   << bytes_to_str(p_bytes)
  end
  puts plain
end

def decrypt_ctr(key,cipher)
  iv, *blocks = cipher.scan(/[0-9A-Fa-f]{32}/)

  iv_bytes = hexstr_bytes(iv)
  k_str  = bytes_to_str(hexstr_bytes(key))
  iv_str = bytes_to_str(iv_bytes)
  
  # get the bytes that are more than iv+blocks * 32 ( chars )
  pad_size = (cipher.length - ( (blocks.length+1)*32 ))
  str = cipher[-1 * pad_size,pad_size]
  blocks << str

  plain= ""
  blocks.each_with_index do |block,i|
    c_bytes = hexstr_bytes(block)
    c_str = bytes_to_str(c_bytes)
  
    cur_iv_bytes     = iv_bytes.dup
    cur_iv_bytes[-1] = cur_iv_bytes.last+i
    cur_iv_str = bytes_to_str(cur_iv_bytes)
  
    _,d_str = AES.encrypt(cur_iv_str, key, {:format => :plain,:padding => true,:cipher => "AES-128-ECB" })
    d_bytes = d_str.bytes.to_a
    p_bytes = xor_bytes(d_bytes,c_bytes)
    plain   << bytes_to_str(p_bytes)
  end
  puts plain
end

if $0 == __FILE__ 
  CryptStr.new("FFAABB").xor("0xaa").xor("d2 ee").pp
end

