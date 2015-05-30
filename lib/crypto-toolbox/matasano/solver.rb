require 'crypto-toolbox/matasano/sets/set1.rb'
require 'crypto-toolbox/matasano/sets/set2.rb'
require 'crypto-toolbox/matasano/sets/set3.rb'

module Matasano
  class Solver
    include Matasano::Sets::Set1
    include Matasano::Sets::Set2
    include Matasano::Sets::Set3
  end
end
