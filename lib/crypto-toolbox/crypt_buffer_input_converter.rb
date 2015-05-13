

class CryptBufferInputConverter
  def convert(input)
    bytes_from_any(input)
  end

  # Make sure input strings are always interpreted as hex strings
  # This is especially useful for unknown or uncertain inputs like
  # strings with or without leading 0x
  def from_hex(input)
    hexstr =""
    unless input.nil?
      hexstr = normalize_hex(input)
    end
    CryptBuffer.new(hex2bytes(hexstr))
  end
  
  def from_base64(input)
    string = Base64.decode64(input)
    CryptBuffer.new(str2bytes(string))
  end
  
  private
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
    when NilClass
      []
    else
      raise "Unsupported input: #{input.inspect} of class #{input.class}"
    end
  end

  def int2bytes(input)
    [input].pack('C*').bytes
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
  
  def pad_hex_char(str)
    (str.length == 1) ? "0#{str}" : "#{str}"
  end
  
  def normalize_hex(str)
    tmp = pad_hex_char(str)
    tmp.gsub(/(^0x|\s)/,"").upcase
  end

end

def CryptBuffer(input)
  bytes = CryptBufferInputConverter.new.convert(input)
  CryptBuffer.new(bytes)
end
