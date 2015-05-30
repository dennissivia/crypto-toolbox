require 'base64'

require 'crypto-toolbox/utils/reporting/console.rb'
require 'crypto-toolbox/utils/hamming_distance_filter.rb'
require 'crypto-toolbox/utils/ecb_detector.rb'
require 'crypto-toolbox/utils/ecb_oracle.rb'

require 'crypto-toolbox/oracles/user_profile_encryption_oracle.rb'
require 'crypto-toolbox/oracles/cbc_mutating_encryption_oracle.rb'

require 'crypto-toolbox/oracles/padding_oracle/tcp_oracle.rb'
require 'crypto-toolbox/oracles/padding_oracle/http_oracle.rb'
require 'crypto-toolbox/oracles/padding_oracle/memory_oracle.rb'




require 'crypto-toolbox/crypt_buffer_input_converter.rb'
require 'crypto-toolbox/crypt_buffer.rb'

require 'crypto-toolbox/analyzers/utils/key_filter.rb'
require 'crypto-toolbox/analyzers/utils/letter_frequency.rb'
require 'crypto-toolbox/analyzers/utils/ascii_language_detector.rb'
require 'crypto-toolbox/analyzers/utils/spell_checker.rb'
require 'crypto-toolbox/analyzers/utils/human_language_detector.rb'


require 'crypto-toolbox/analyzers/padding_oracle.rb'
require 'crypto-toolbox/analyzers/cbc_mac.rb'
require 'crypto-toolbox/analyzers/vigenere_xor.rb'
require 'crypto-toolbox/analyzers/ecb_string_appender.rb'
require 'crypto-toolbox/analyzers/cbc_mutating_encryption.rb'


require 'crypto-toolbox/ciphers/aes.rb'
require 'crypto-toolbox/ciphers/caesar.rb'
require 'crypto-toolbox/ciphers/rot13.rb'

require 'crypto-toolbox/forgers/stream_ciphers/forge_generator.rb'


require 'crypto-toolbox/matasano/solver.rb'
