require 'rspec'
require 'crypto-toolbox'

require 'coveralls'
Coveralls.wear!

RSpec.configure do |config|
  config.failure_color = :magenta
  config.tty = true
  config.color = true
  config.filter_run_including :focus => true
  config.filter_run_including :wip => true
  config.run_all_when_everything_filtered = true
  config.fail_fast = false
end
