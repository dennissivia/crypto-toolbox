require 'crypto-toolbox'
require 'pry'
require 'pp'

class CryptoAnalyzer
  class OneTimePad
  end
end


cipher_texts = %w(
BB3A65F6F0034FA957F6A767699CE7FABA855AFB4F2B520AEAD612944A801E
BA7F24F2A35357A05CB8A16762C5A6AAAC924AE6447F0608A3D11388569A1E
A67261BBB30651BA5CF6BA297ED0E7B4E9894AA95E300247F0C0028F409A1E
A57261F5F0004BA74CF4AA2979D9A6B7AC854DA95E305203EC8515954C9D0F
BB3A70F3B91D48E84DF0AB702ECFEEB5BC8C5DA94C301E0BECD241954C831E
A6726DE8F01A50E849EDBC6C7C9CF2B2A88E19FD423E0647ECCB04DD4C9D1E
BC7570BBBF1D46E85AF9AA6C7A9CEFA9E9825CFD5E3A0047F7CD009305A71E
)
ascii_blacklist = [40,41,42,43,47,60,61,62,91,92,93,94,95,96,    35,59] # # ; 
ascii_whitelist = (32..123).to_a - ascii_blacklist

keylen=CryptBuffer.new(cipher_texts.first).bytes.length
#m1m2_pairs = cipher_texts.combination(2)

## NOTE: vigenere decrypter should get cipher and keylen as constructor args
## NOTE: just pass the concatenation of all strings to the vigenere cipher solver ?? 
## NOTE: Alternative algorithm: create all permutations of cipher texts, xor them to get m1m2 and xor (loop 32 - 123 ) any ASCII out and check if the result is also ASCII


matches = []
(0..keylen-1).each do |pos|
  tmp=[]
  (1..255).each do |guess|
    if cipher_texts.map{|c| CryptBuffer.new(CryptBuffer.new(c).bytes[pos]).xor(guess).bytes.first }.
       all?{|byte| puts byte.inspect ; byte > 32 && byte < 123 && ! ascii_blacklist.include?(byte) }
      #puts cipher_texts.map{|c| CryptBuffer.new(CryptBuffer.new(c).bytes[pos]).xor(guess).str }.inspect
      tmp << guess
    end
  end
  matches << tmp
end
matches.map!{|e| e.sort}
puts matches.inspect
puts matches.map{|e| e.length}.reduce(&:*)
matches.each do |arr|
  puts arr.inspect
end
matches.map!{|i|i.compact}
possible_key_bytes = matches



=begin
possible_key_bytes={}

(0..keylen-1).to_a do |pos|
  possible_key_bytes[pos] = (1..255).to_a
end
=end


def combinations_for(ct,index)
  cn         = (1..ct.length).map{|i| "c#{i}"}
  names      = cn.combination(2).map{|a,b| "#{a},#{b}"}
  puts ct[index]

  val        = ct[index]
  base,rest = ct.partition{|e| e == val}

  combis     = base.product(rest).map{|l,r| CryptBuffer.new(l).xor(r)}
  combis
end

cipher_texts.each_with_index do |sample,index|
  puts "==========================================="
  puts "processing combinations with cipher #{index}"
  combis = combinations_for(cipher_texts,index)
  result = combis.map{|combi| combi.xor_space.chars.map{|c| c.match(/[a-zA-Z]/).nil? ? nil : c } }
                       #.map{|c| ( ascii_whitelist.include?(c.bytes.first) || c.bytes.first.zero? ) ? c : nil }}  
  result.each do |r|
    puts r.inspect
  end
end 

binding.pry
# permutations


result={}
(0..keylen-1).each do|pos|
  result[pos] ||= [ ]
  ascii_whitelist.each do |abyte|
    begin
      binding.pry
      
      #combis  = [head].product(tail).map{|l,r| CryptBuffer.new(l).xor(r)}
      valid_guess = combis.map{|combi| CryptBuffer.new(CryptBuffer.new(combi).bytes[pos]).xor(abyte).bytes.first}.all?{|byte| ascii_whitelist.include?(byte) }

      if valid_guess
        
        result[pos] << CryptBuffer.new(abyte).xor(cipher_texts[0]).bytes.first
      end
    rescue => ex
      binding.pry
    end
  end
end
binding.pry

exit

=begin

NOTE: alternative implementation using whitespace and ascii bruteforce detection

result=[];
(0..(cipher_texts.length() -1)).each do |i|
   combis = combinations_for(cipher_texts,i)          
   result << combis  
end
x = result.flatten

def test_plain(all,plain)
  ascii_blacklist = [40,41,42,43,47,60,61,62,91,92,93,94,95,96,    35,59] # # ; 
  ascii_whitelist = (32..123).to_a - ascii_blacklist
  all.map{|combi| combi.xor(plain + (" "*31)).bytes.map{|byte| ascii_whitelist.include?(byte) ? byte : "_".bytes.first } }.map{|e| CryptBuffer.new(e).str}
end

tmp = test_plain(x,"I am ")
tmp.map{|e| spell.known_words(e).count}.reduce(&:+)
tmp.map{|e| spell.known_words(e)}.map{|arr| arr.select{|e| e =~ /[a-zA-Z]/}



x.map{|combi| combi.xor("I am p                                             ").chars} 
x.map{|combi| combi.xor("When should we meet to do this?").str}


 "I am planning a secret mission.",
 "He is the only person to trust.",
 "The current plan is top secret.",
 "I am planning a secret mission.",
 "He is the only person to trust.",
 "The current plan is top secret.",
 "I think they should follow him.",
 "This is purer than that one is.",
 "Not one cadet is better than I.",
 "I think they should follow him.",
 "This is purer than that one is.",
 "Not one cadet is better than I.",
 "When should we meet to do this?"
=end


=begin
kinda works...
#  combinations = cs.
c1c2_combs = combis.map.with_index do |(l,r),i|
  c1c2 = CryptBuffer.new(l).xor(r)
  puts "#{names[i]}: "
  x = {}
  #  ascii_whitelist.map{|byte| c1c2.xor(byte).bytes.first }.select{|b| ascii_whitelist.include?(b)}
  c1c2.bytes.each_with_index do |byte,pos|
    ascii_whitelist.each do |abyte|
      x[pos] ||= []
      b =CryptBuffer.new(byte).xor(abyte).bytes.first
      x[pos] << b if ascii_whitelist.include?(b)
    end
  end
  binding.pry  

#    m1m2.each do |byte|
#      print ( (byte.chr =~ /[[:print:]]/) ? byte.chr : "_" )
#    end
#    print "\n"
  #end
end
=end

=begin
# printout for debugging. (Manual analysis of the characters)
puts "======= Candidate decryption result of first #{keylen} bytes ======="
puts "working with ciphertext one only"
buf = CryptBuffer.new(cipher_texts.first)
message = ""
(0..keylen-1).each do|pos|
  key = matches.map{|m| m[pos]}
  puts key.inspect
  string = buf.xor(key).to_s
  puts string
  #matches[pos].each do |byte|
  #  print CryptBuffer.new(buf.bytes[pos]).xor(byte).to_s + " "
  ##end
  #print "\n"
end
puts "====================================================================="
=end

=begin
buf = CryptBuffer.new(cipher_texts.first)
#puts matches.inspect
head,*tail = matches
spell = SpellChecker.new("en_GB")
c = 0
begin
  possible_keys = head.product(*tail) do |i|
    
    mes = buf.xor(i).str
    c+=1
    if(c % 50000).zero?
      puts "[Progress] #{c}"
    end
    if mes.include?(" ") && spell.check(mes)
      binding.pry
    else
    end

  end
rescue RangeError => ex
  puts "cannot use all key permutations, products calculation error: (#{ex.message})"
end

=end
