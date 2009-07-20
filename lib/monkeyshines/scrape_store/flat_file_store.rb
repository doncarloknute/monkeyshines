require 'fileutils'; include FileUtils

module Monkeyshines
  module ScrapeStore
    #
    class FlatFileStore < ScrapeStore::Base
      attr_accessor :filename, :filemode

      #
      # +filename_root+  : first part of name for files
      #
      def initialize filename, options={}
        self.filename = filename or raise "Missing filename in #{self.class}"
        self.filemode = options[:filemode] || 'a'
      end

      #
      #
      #
      def each &block
        file.each do |line|
          attrs = line.chomp.split("\t")
          next if attrs.blank?
          yield *attrs
        end
      end

      #
      # Read ahead n_lines lines in the file
      #
      def skip! n_lines
        Monkeyshines.logger.info "Skipping #{n_lines} in #{self.class}:#{filename}"
        n_lines.times do
          file.readline
        end
      end

      #
      # Open the timestamped file,
      # ensuring its directory exists
      #
      def file
        return @file if @file
        Monkeyshines.logger.info "Opening file #{filename} with mode #{filemode}"
        @file = File.open(filename, filemode)
      end

      # Close the dump file
      def close
        @file.close if @file
        @file = nil
      end

      # Ensure the file's directory exists
      def mkdir!
        dir = File.dirname(filename)
        return if File.directory?(dir)
        Monkeyshines.logger.info "Making directory #{dir}"
        FileUtils.mkdir_p dir
      end

      # write to the file
      def save obj
        file << obj.to_flat.join("\t")+"\n"
      end

      # delegates to +#save+ -- writes the object to the file
      def <<(obj)
        save obj
      end

      #
      # take a hash of options:
      #
      #   --from
      #   --filemode
      #
      def self.new_from_command_line cmdline_opts, default_opts={}
        options = default_opts.merge(cmdline_opts)
        self.new options[:from], options
      end
    end
  end
end

