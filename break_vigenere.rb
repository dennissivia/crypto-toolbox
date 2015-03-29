# coding: utf-8
load 'crypt_buffer.rb'
require 'shellwords'
require 'ffi/hunspell'

##
# http://www.ulduzsoft.com/2015/03/breaking-the-vigenere-cipher/
# https://github.com/trekawek/vigenere/blob/master/vig.rb

def find_pattern(buf)
  bitstring = buf.bits.map{|b| b[0]}.join("")
  1.upto(16).map do |ksize|
    parts = bitstring.scan(/.{#{ksize}}/)
    if parts.uniq.length == 1
      parts.first
    else
      nil
    end
  end.compact.first
end

input = ARGV[0] || "F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794"

buf = CryptBuffer.new(input)
result = find_pattern(buf)

if result.nil?
  $stderr.puts "failed to find keylength by ASCII-8-Bit anlysis"
  exit(1)
end

keylen = result.length
puts "Found recurring key pattern: #{result}"
puts "Detected key length: #{keylen}"

candidate_map ={}
(0..(keylen-1)).each do |key_byte|

  nth_stream = (key_byte).step(buf.bytes.length() -1, keylen).map{|i| buf.bytes[i]}
  smart_buf = CryptBuffer.new(nth_stream)

  candidate_map[key_byte]=[]
  1.upto(255).each do |possible_key_value|
    if smart_buf.xor_all_with(possible_key_value).bytes.all?{|e| e > 31 && e < 123 && e != 60 && e !=64}
      #puts  "YES: " + smart_buf.xor_all_with(possible_key_value).to_s
      candidate_map[key_byte] << possible_key_value
    else
      #puts  "NO: " + smart_buf.xor_all_with(possible_key_value).to_s
    end
  end
end



head,*tail = candidate_map.map{|k,v|v}

puts "Amount of candidate keys: #{candidate_map.map{|k,v| v.length}.reduce(&:*)}. Starting Permutation (RAM intensive)"

combinations = head.product(*tail)
# make sure all permutations are still according to the bytes per position map
#x = combinations.select do |arr|
#  #binding.pry
#  arr.map.with_index{|e,i| candidate_map[i].include?(e)  }.all?{|e| e ==true}
#end

# printout for debugging. (Manual analysis of the characters)
puts "======= Candidate decryption result of first #{keylen} bytes ======="
(0..keylen-1).each do|i|
  candidate_map[i].each do |byte|
    print CryptBuffer.new(buf.bytes[i,keylen]).xor(byte).to_s +  " "
  end
  print "\n"
end
puts "====================================================================="

times = buf.bytes.length / keylen
dict = FFI::Hunspell.dict('en_GB')

combinations.each_with_index do |key,i| #  i is used as a simple counter only !
  test = CryptBuffer.new(buf.bytes[0,keylen]).xor(key).str
  repkey = (key*times) + key[0,(buf.bytes.length % times).to_i]
    str    = buf.xor(repkey).to_s
    words  = str.split(" ").length
    errors = str.split(" ").map{|e| dict.check?(e) }.count{|e| e == false}
    # using shell instead of hunspell ffi causes lots of escaping errors, even with shellwords.escape
    #errors = Float(`echo '#{Shellwords.escape(str)}' |hunspell -l |wc -l `.split.first)

    error_rate = errors.to_f/words
    $stderr.puts error_rate.round(4)


=begin
missing punctuation support may lead to > 2% errors on valid texts, thus we use a high value .
invalid decryptions tend to have spell error rates > 70
Some statistics about it:
> summary(invalids)
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max. 
 0.6000  1.0000  1.0000  0.9878  1.0000  1.0000 
> summary(cut(invalids,10))
 (0.6,0.64] (0.64,0.68] (0.68,0.72] (0.72,0.76]  (0.76,0.8]  (0.8,0.84] 
          8          13           9         534        1319        2809 
(0.84,0.88] (0.88,0.92] (0.92,0.96]    (0.96,1] 
      10581       46598      198477     1440651 
=end
    if error_rate > 0.5
      

      if (i % 50000).zero?
        #puts "skipping #{str} (spell error_rate: #{error_rate})"
        puts "[Progress] #{i}/#{combinations.length} (#{(i.to_f/combinations.length*100).round(4)}%)"
      end
    else
      puts "[Success] Found valid result (spell error_rate: #{error_rate*100}% is below threshold: 20%)"
      puts "#{str}"
    end
end

=begin
NOTE: we may at digram and trigram support?
#trigram="the "
#x = CryptBuffer.new(trigram)
=end







