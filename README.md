# crypto-toolbox
Small toolbox for simple Crypto analysis and learning applied cryptography techniques.


[![Build Status](https://travis-ci.org/scepticulous/crypto-toolbox.svg?branch=master)](https://travis-ci.org/scepticulous/crypto-toolbox)
[![Code Climate](https://codeclimate.com/github/scepticulous/crypto-toolbox/badges/gpa.svg)](https://codeclimate.com/github/scepticulous/crypto-toolbox)
[![Coverage Status](https://coveralls.io/repos/scepticulous/crypto-toolbox/badge.svg?branch=master)](https://coveralls.io/r/scepticulous/crypto-toolbox?branch=master)
[![Gem Version](https://badge.fury.io/rb/crypto-toolbox.svg)](http://badge.fury.io/rb/crypto-toolbox)

# CryptBuffer 
The CryptBuffer is made to make Xor operations on strings, bytes, hex-strings easy.

## Input Conversion

```ruby
# Strings beginning with 0x are handles has hex strings
CryptBuffer("0xFFeecc")
=> #<CryptBuffer:0x000000010d8e18 @bytes=[255, 238, 204]>

# Hex Integers are supported
CryptBuffer(0xFFeecc)
=> #<CryptBuffer:0x000000010d8e18 @bytes=[255, 238, 204]>

# regular strings are supported
CryptBuffer("my example String")
=> #<CryptBuffer:0x00000000f353b8 @bytes=[109, 121, 32, 101, 120, 97, 109, 112, 108, 101, 32, 83, 116, 114, 105, 110, 103]>

# Strings without leading 0x are handled as strings to avoid ambiguities
CryptBuffer("FFeecc")
=> #<CryptBuffer:0x0000000091ea60 @bytes=[70, 70, 101, 101, 99, 99]>
# AND not 255, 238, 204


# Numers are treated as bytes but: numbers with a leading 0x are treated has hex bytes
CryptBuffer(64)
=> #<CryptBuffer:0x00000000644d08 @bytes=[64]> 
CryptBuffer(0x64)
=> #<CryptBuffer:0x00000000619ae0 @bytes=[100]> 
```
### from_hex
To force hextring interpretation of a input string one can also use from_hex.
This is useful if the formatting of the input is uncertain.

```ruby
CryptBuffer.from_hex("f").hex
=> "0F"

CryptBuffer.from_hex("0x0f").hex
=> "0F"

CryptBuffer.from_hex("0F").hex
 => "0F"

```


## XORing

### CryptBuffer#xor
Xoring two CryptBuffers
```ruby
key = CryptBuffer("my-super-secret-key")
str = CryptBuffer("my-public-message!!")
cipher = key.xor(str)
```

Xor any compatible input for a Cryptbuffer:
```ruby
key="my-super-secret-key"
msg="my-public-message!!"

CryptBuffer(key).xor(msg).xor(CryptBuffer(key)).str
 => "my-public-message!!" 

CryptBuffer(" ").xor("u").str
=> "U"

CryptBuffer("u").xor(1).str
=> "t"

CryptBuffer(0x90).xor(1).xor("0xff").str
 => "n" 
 ```


### CryptBuffer#xor_at(val,pos)
```ruby
buf = CryptBuffer([1,1,2,2,3,3]) }

buf.xor_at(200,0).bytes
=> [201,1,2,2,3,3]

# it also allows negative array-like indexing

buf.xor_at(200,-1).bytes
=> [1,1,2,2,3,203]

```

### CryptBuffer#xor_all_with(byte)
```ruby
buf = CryptBuffer([1,1,1]) }

buf.xor_all_with(200).bytes
=> [201,201,201]
```


### CryptBuffer#xor_space
Simple shorthand for

```ruby
CryptBuffer(input).xor(0x20)
```



## Method Chaining
```ruby
CryptBuffer("secret-key").xor("my message").xor_all_with(0x20).xor("secret-key").xor_all_with(0x20).str
=> "my message"
```

## Arithmetic
### add(n,mod)
add allows to add a certain value to every byte in the buffer:

```ruby
CryptBuffer("0xFeFeFe").add(1).hex == "FFFFFF"
=> true
```

It also allows to a custom modulus for the addition
```ruby
CryptBuffer("0x0f").add(15,mod:20).bytes  == 10
=> true
```

## nth_bits(n) | 0 <= n <= 7
Returns the nths bits of each byte (starting with the least significant bit):

```ruby
# index 0..7

buf = CryptBuffer("0xFECDE993").bits
 => ["11111110", "11001101", "11101001", "10010011"] 
       
buf = CryptBuffer("0xFECDE993").nth_bits(2)
 => [1, 1, 0, 0]
```


## Output conversion

```ruby
buf = CryptBuffer("0xfecc993")

buf.to_s
=> "\xFE\xCC\x99"
buf.chars
=> ["\xFE", "\xCC", "\x99"]
buf.bytes
=> [254, 204, 153]
buf.hex
=> "fecc99"

CryptBuffer(1).bits
=> ["00000001"]

CryptBuffer("AABB")
=> ["10101010", "10111011"]

```


Shortcut methods are: 
```ruby
s => to_s
h => hex
b => bytes
c => chars
```

## Debug output 
pp method:
```ruby
CryptBuffer("0xfecc993").pp
=> 0xFECC99 (FE CC 99)
```

## Caesar Cipher
Based on the CryptBuffer a sample Caesar Cipher implementation will be shipped

```ruby
Ciphers::Caesar.encipher("AAAA","A") == "AAAA"

Ciphers::Caesar.decipher("BBBB","B") == "AAAA"
Ciphers::Caesar.decipher("AAAA","B") == "ZZZZ"
```

## Rot13
Based on the Caesar Cipher a Rot13 is contained as well. 
```ruby
# since rot13 is invertable
Ciphers::Rot13.encipher("AAAA") == "NNNN"
Ciphers::Rot13.decipher("AAAA") == "NNNN"

# thus the shorthand is:
Ciphers::Rot13.apply("AAAA") == "NNNN"
