#!/usr/bin/env ruby

require "crypto-toolbox"
require "pry"

key="supersecret"
marys_lamp = CryptBuffer(File.read("marys-lamp.txt")).xor(key,expand_input: true).base64(strict: false)
puts "key was: #{key} with length: #{key.length}"

File.open("marys-lamp.base64.txt","w") do|f|
  f.puts marys_lamp
end
res = CryptoChallanges::Solver.new.solve6(File.read("marys-lamp.base64.txt")).first.str
puts res

key2="supersecretkeynumer2"
marys_lamp = CryptBuffer(File.read("marys-lamp.txt")).xor(key2,expand_input: true).base64(strict: false)
puts "key was: #{key2} with length: #{key2.length}"
File.open("marys-lamp.base64-2.txt","w") do|f|
  f.puts marys_lamp
end
res = CryptoChallanges::Solver.new.solve6(File.read("marys-lamp.base64-2.txt")).first.str
puts res
