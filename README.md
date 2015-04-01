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

CryptBuffer(64)
=> #<CryptBuffer:0x000000010d60f0 @bytes=[64]>
```

#### Simple Xoring

```ruby
key = CryptBuffer("my-super-secret-key")
str = CryptBuffer("my-public-message!!")
cipher = key.xor(str)
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
