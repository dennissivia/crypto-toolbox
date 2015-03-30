require 'ffi/hunspell'
class SpellChecker
  def initialize(dict_lang="en_GB")
    @dict = FFI::Hunspell.dict(dict_lang)
  end
=begin
NOTE: About spelling error rates and language detection:

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
  def check(str)
    words  = str.split(" ").length
    errors = str.split(" ").map{|e| @dict.check?(e) }.count{|e| e == false}
    # using shell instead of hunspell ffi causes lots of escaping errors, even with shellwords.escape
    #errors = Float(`echo '#{Shellwords.escape(str)}' |hunspell -l |wc -l `.split.first)

    error_rate = errors.to_f/words
          
    $stderr.puts error_rate.round(4) if ENV["CRYPTO_TOOBOX_PRINT_ERROR_RATES"]

    if error_rate < 0.5
      puts "[Success] Found valid result (spell error_rate: #{error_rate*100}% is below threshold: 20%)"
      return true
    else
      return false
    end
  end

    
end
