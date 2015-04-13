require 'benchmark/ips'

Benchmark.ips do |x|
  x.time = 5
  x.warmup = 2

  input="A"
  x.report("string.bytes.first == A")  { byte=input.bytes.first; ( byte>= 97 && byte <= 122) || (byte > 65 && byte < 90) }
  x.report("string =~ [A-Za-Z]")       { input =~ /[A-Za-z]/ }
  x.report("Letter Array build+include?(A)") { (("a".."z").to_a + ("A".."Z").to_a).include?(input) }

  # precalculate the char array 
  arr= (("a".."z").to_a + ("A".."Z").to_a)
  x.report("Letter Array include?(A)") { arr.include?(input) }
  x.report("Array#bsearch{}.nil?") { arr.bsearch{|c| c == input }.nil? }
           
  x.compare!
end
