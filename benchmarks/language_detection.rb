require 'crypto-toolbox'
require 'benchmark/ips'

def hunspell_human_language_without_dict(input, candidates, dict, filter)
  candidates.select{|buf| Analyzers::Utils::SpellChecker.new.human_language?(buf.str) }
end

def ascii_lingual_and_human_language(input, candidates, dict, filter)
  candidates.select{|buf| filter.ascii_lingual?(buf) }.select{|b| dict.human_language?(b.str) }
end

def ascii_lingual(input, candidates, dict, filter)
  candidates.select{|b| filter.ascii_lingual?(b) }.select{|b| dict.human_language?(b.str) }
end

def ascii_lingual_byte(input, candidates, dict, filter)
  candidates.select{|buf| buf.bytes.all?{|b| filter.ascii_lingual_byte?(b) } }.select{|b| dict.human_language?(b.str) }
end

def ascii_lingual_bytes(input, candidates, dict, filter)
  candidates.select{|buf| filter.ascii_lingual_bytes?(buf.bytes) }.select{|b| dict.human_language?(b.str) }
end

def ascii_whitelist_include(input, candidates, dict, filter)
  candidates.select{|buf| buf.bytes.all?{|b| filter.ascii_lingual_chars.include?(b) } }.select{|b| dict.human_language?(b.str) }
end

def ascii_whitelist_bsearch(input, candidates, dict, filter)
  candidates.select{|buf| buf.bytes.all?{|b| !!filter.ascii_lingual_chars.bsearch{|i| i == b} } }.select{|b| dict.human_language?(b.str) }
end

def ascii_range_check(input, candidates, dict, filter)
  range=(32..127)
  blacklist=  [40,41,42,43,47,60,61,62,91,92,93,94,95,96,35,59]
  candidates.select{|buf| buf.bytes.all?{|b| range.cover?(b) && !blacklist.include?(b) } }.select{|b| dict.human_language?(b.str) }
end

def ascii_shift_check(input, candidates, dict, filter)
  candidates.select{|buf| buf.bytes.all?{|b| b < 127 && !(b.chr.downcase.ord & (1 << 5)).zero? } }.select{|b| dict.human_language?(b.str) }
end

def hunspell_human_language(input, candidates, dict, filter)
   candidates.select{|buf| dict.human_language?(buf.str) }
end

dict   = Analyzers::Utils::SpellChecker.new
filter = Analyzers::Utils::AsciiLanguageDetector.new
input="746865206b696420646f6e277420706c6179"
candidates = (1..256).map{ |guess| CryptBuffer.from_hex(input).xor_all_with(guess) }

Benchmark.ips do |x|
  x.time = 5
  x.warmup = 2  

  x.report("hunspell_human_language_without_dict") { hunspell_human_language_without_dict(input, candidates, dict, filter) }
  x.report("ascii_lingual_and_human_language")     { ascii_lingual_and_human_language(input, candidates, dict, filter) }
  x.report("hunspell.human_language?")   { hunspell_human_language(input, candidates, dict, filter) }
  x.report("ascii_whitelist.include?")   { ascii_whitelist_include(input,candidates, dict, filter) }
  x.report("ascii_whitelist.bsearch?")   { ascii_whitelist_bsearch(input,candidates, dict, filter) }
  x.report("ascii_lingual_byte?")  { ascii_lingual_byte(input, candidates, dict, filter) }
  x.report("ascii_lingual_bytes?") { ascii_lingual_bytes(input, candidates, dict, filter) }
  x.report("ascii_lingual?")       { ascii_lingual(input, candidates, dict, filter) }
  x.report("ascii_range_check")    { ascii_range_check(input, candidates, dict, filter) }
  x.report("ascii_shift_check")     { ascii_shift_check(input, candidates, dict, filter) }
  x.compare!
end
