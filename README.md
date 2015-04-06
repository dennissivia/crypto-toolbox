# crypto-toolbox
Small toolbox for simple Crypto analysis and learning applied cryptography techniques.

## CryptBuffer
The CryptBuffer is made to make Xor operations on strings, bytes, hex-strings easy.

### Usage Examples
#### Input Type conversion

```ruby
CryptBuffer("0xFFeecc")
=> #<CryptBuffer:0x000000010d8e18 @bytes=[255, 238, 204]>

CryptBuffer("FFeecc")
=> #<CryptBuffer:0x000000010d8e18 @bytes=[255, 238, 204]>

CryptBuffer(0xFFeecc)
=> #<CryptBuffer:0x000000010d8e18 @bytes=[255, 238, 204]>

CryptBuffer("my example String")
=> #<CryptBuffer:0x00000000f353b8 @bytes=[109, 121, 32, 101, 120, 97, 109, 112, 108, 101, 32, 83, 116, 114, 105, 110, 103]>



# Numers are treated as bytes but: numbers with a leading 0x are treated has hex bytes

CryptBuffer(64)
=> #<CryptBuffer:0x00000000644d08 @bytes=[64]> 
CryptBuffer(0x64)
=> #<CryptBuffer:0x00000000619ae0 @bytes=[100]> 
```

#### XORing

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



#### Method Chaining
```ruby
CryptBuffer("secret-key").xor("my message").xor_all_with(0x20).xor("secret-key").xor_all_with(0x20).str
=> "my message"
```
####
Enumerable


#### Output conversion

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

#### Debug output 
pp method:
```ruby
CryptBuffer("0xfecc993").pp
=> 0xFECC99 (FE CC 99)
