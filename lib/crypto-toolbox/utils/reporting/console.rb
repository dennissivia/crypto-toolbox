module Utils
  module Reporting
    module Console
      # Print to stdout with support of debug conditions
      # This is especially helpfull if the analysis fails or is too slow
      def jot(message, debug: false,raw: false)
        if debug == false || ENV["DEBUG_ANALYSIS"]
          raw ? print_raw(message) : print_nice(message)
        end
      end
      def print_delimiter_line
        puts "=====================================================================" 
      end

      def print_raw(msg)
        print msg
      end
      def print_nice(msg)
        puts msg
      end
    end
  end
end
