Welcome to my sollution of the Matasano Crypto Challanges
=========================================================
This documentation is generated using [knitr](http://yihui.name/knitr/)

**Solutions using the CryptoToolbox**

# Set1
## Challange1

**Convert hex to base64**

```ruby
  require 'crypto-toolbox'
  input="49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
  
  puts CryptBuffer.from_hex(input).base64
```

```
## SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

## Challange2
**Fixed XOR**


```ruby
  require 'crypto-toolbox'
  
  c1 = "1c0111001f010100061a024b53535009181c"
  c2 = "686974207468652062756c6c277320657965"
  puts (CryptBuffer.from_hex(c1) ^ CryptBuffer.from_hex(c2)).hex.downcase
```

```
## 746865206b696420646f6e277420706c6179
```
## Challange3
**Single Byte XOR**


```ruby
  require 'crypto-toolbox'
  input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

  candidates = (1..256).map{ |guess| CryptBuffer.from_hex(input).xor_all_with(guess) }
  detector = Analyzers::Utils::HumanLanguageDetector.new

  result = detector.human_language_entries(candidates).first.to_s
  puts "I wont show the result here"
```

```
## I wont show the result here
```
