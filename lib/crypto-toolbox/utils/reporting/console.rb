module Utils
  module Reporting
    module Console
      # Print to stdout with support of debug conditions
      # This is especially helpfull if the analysis fails or is too slow
      def jot(message, debug: false)
        if debug == false || ENV["DEBUG_ANALYSIS"]
          puts message
        end
      end
      def print_delimiter_line
        puts "=====================================================================" 
      end
    end
  end
end
