Gem::Specification.new do |s|
  s.name        = 'crypto-toolbox'
  s.version     = '0.0.5'
  s.date        = '2015-04-08'
  s.summary     = "Toolbox for crypto analysis"
  s.description = "The Crypto Toolbox offers some tools to easily work with cryptographic primitives like arrays of Bytes or hextrings"
  s.authors     = ["Dennis Sivia"]
  s.email       = 'dev@d-coded.de'
  s.files       = Dir.glob("lib/**/*.rb")
  s.homepage    = 'https://github.com/scepticulous/crypto-toolbox'
  s.license     = 'GPLv3'

  s.add_dependency 'aes', '~> 0.5'
  s.add_dependency 'ffi-hunspell', '~> 0.3'
#  see Gemfile
#  s.add_development_dependency 'pry'
#  s.add_development_dependency 'rspec', '~> 3.2'
end
