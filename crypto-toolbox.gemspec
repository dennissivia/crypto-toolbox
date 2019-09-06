spec = Gem::Specification.new do |s|
  s.name        = 'crypto-toolbox'
  s.version     = File.read("./VERSION").strip
  s.date        = Time.now.strftime("%Y-%m-%d")
  s.summary     = "Toolbox for crypto analysis"
  s.description = <<-EOF
    Easily work with primitives like arrays of Bytes or hextrings, to make learning und testing cryptographic methods work like a charme.
EOF
  s.authors     = ["Dennis Sivia"]
  s.email       = 'dev@d-coded.de'
  s.files       = Dir.glob("lib/**/*.rb")
  s.homepage    = 'https://github.com/scepticulous/crypto-toolbox'
  s.license     = 'GPLv3'
  s.required_ruby_version = '>= 2.2'

  s.executables << "break-vigenere-xor"
  s.executables << "break-padding-oracle"
  s.executables << "break-cbc-mac-variable-length"
  s.executables << "break-ecb-string-appender"

  s.add_dependency 'aes', '~> 0.5.0'
  s.add_dependency 'ffi-hunspell', '~> 0.4.0'
end

