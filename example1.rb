load "crypt_buffer.rb"
a = "0xA8"
b = "0xED"
c = "0xBD"
bc = CryptBuffer.new(b).xor(c)
bcp = CryptBuffer.new(b).xor(c).xor_space

puts "CryptBuffer.new(#{b}).xor(#{c}).xor_space evals to:"
puts "plain character: #{bcp.chars}"

a=0xB7
b=0xE7
plain = CryptBuffer.new(a).xor(b).xor_space
puts "CryptBuffer.new(#{a}).xor(#{b}).xor_space evals to:"
puts "plain character: #{plain.chars}"


a = 0x66
b = 0x32
c = 0x23

puts "multi-time pad analysis for #{a}, #{b}, #{c}"
puts CryptBuffer.new(a).xor(b).xor_space.chars.inspect
puts CryptBuffer.new(a).xor(c).xor_space.chars.inspect
puts CryptBuffer.new(b).xor(c).xor_space.chars.inspect
