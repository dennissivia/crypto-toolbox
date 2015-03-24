load "crypt_buffer.rb"
a = "0xA8"
b = "0xED"
c = "0xBD"
bc = CryptBuffer.new(b).xor(c)
bcp = CryptBuffer.new(b).xor(c).xor_space
puts "CryptBuffer.new(#{b}).xor(#{c}).xor_space evals to:"
puts "plain character: #{bcp.chars}"
