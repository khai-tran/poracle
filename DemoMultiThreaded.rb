##
# Demo.rb
# Created: February 10, 2013
# By: Ron Bowes
#
# A demo of how to use Poracle, that works against RemoteTestServer.
##
#
# coding: utf-8
require 'httparty'
require './poracle'
require 'optparse'
require './thread/pool'
require 'ostruct'

class Demo
  attr_reader :iv, :data, :blocksize,:newlinechars,:url,:starting_block
  NAME = "Demo"
  # This function should load @data, @iv, and @blocksize appropriately
  def self.parse(args)
    # The options specified on the command line will be collected in *options*.
    # We set default values here.
    options = OpenStruct.new
    options.file = ""
    options.threadsize = 1
    options.sortfile = false
    options.verbose = false

    opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: Demo.rb [options]"
      opts.separator ""
      opts.separator "Specific options:"

      # Sort temprary results
      opts.on("-s", "--sort", "Sort temporary results") do |s|
        options.sortfile = s
      end

      # Verbose
      opts.on("-v", "--verbose", "Show debug messages") do |v|
        options.verbose = v
      end

      # Threadpool size
      opts.on("-t", "--threads SIZE", "Set threadpool size") do |size|
        options.threadsize = Integer(size)
      end

      # Save to file
      opts.on("-f", "--file FILE","Save temporary results to file") do |file|
        options.file = file
      end

      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end
    end
    opt_parser.parse!(args)
    options
  end

  def initialize()
    @data = HTTParty.get("http://localhost:20222/encrypt").parsed_response
    # Parse 'data' here
    @data = [@data].pack("H*")
    @iv = nil
    @blocksize = 16
  end

  # This should make a decryption attempt and return true/false
  def attempt_decrypt(data)
    result = HTTParty.get("http://localhost:20222/decrypt/#{data.unpack("H*").pop}").parsed_response
    # Match 'result' appropriately
    return result !~ /Fail/
  end

  # Optionally define a character set, with the most common characters first
  def character_set()
    charset=' eationsrlhdcumpfgybw.k:v-/,CT0SA;B#G2xI1PFWE)3(*M\'!LRDHN_"9UO54Vj87q$K6zJY%?Z+=@QX&|[]<>^{}'
    return charset.chars.to_a
  end
end

def self.parse_sessionfile(file)
  results=[]
  text=File.open(file).read
  text.gsub!(/\r\n?/, "\n")
  text.each_line do |line|
    results[Integer(line.split(',',2)[0])]=line.split(',',2)[1].gsub("\n","")
  end
  return results
end

def self.sort_sessionfile(file)
  results=[]
  text=File.open(file).read
  text.gsub!(/\r\n?/, "\n")
  text.each_line do |line|
    results[Integer(line.split(',',2)[0])]=line.split(',',2)[1]
  end
  File.open(file, 'w') do |f|
  end
  results.each_with_index do |result,i|
    File.open(file, 'a') do |f|
      if (result.nil?)
        f << "#{i},\n"
      else
        f << "#{i},#{result}"
      end
    end
  end
end

options = Demo.parse(ARGV)
verbose = options.verbose
file = options.file
skip_blocks=[]
sortfile =options.sortfile
threadsize =options.threadsize

if (sortfile)
  sort_sessionfile(file)
  exit
end

# Read already decrypted block from last time and add them to skip_blocks
results=parse_sessionfile(file)
results.each_with_index do |val,i|
  if (!val.nil? and val!="\n")
  skip_blocks<<i
  end
end

if (verbose)
  puts "Skipping blocks: #{skip_blocks.join(", ")}"
end

mod = Demo.new
if( mod.data.length % mod.blocksize != 0)
  puts("Encrypted data isn't a multiple of the blocksize! Is this a block cipher?")
end

blockcount = mod.data.length / mod.blocksize

puts("> Starting poracle decrypter with module #{mod.class::NAME}")
puts(">> Encrypted length: %d" %  mod.data.length)
puts(">> Blocksize: %d" % mod.blocksize)
puts(">> %d blocks" % blockcount)
iv = "\x00" * mod.blocksize

if (verbose)
  i=0
  blocks = mod.data.unpack("a#{mod.blocksize}" * blockcount)
  blocks.each do |b|
    i = i + 1
    puts(">>> Block #{i}: #{b.unpack("H*")}")
  end
end

start = Time.now

# Specify pool size
pool = Thread.pool(threadsize)
blockcount=mod.data.length / mod.blocksize
# Spawn new thread for each block
(blockcount -1 ).step(1,-1) do |i|
  if (!skip_blocks.include?(i))
    pool.process {
      result=Poracle.decrypt(mod, mod.data, iv,  verbose, i, file)
      results[i]=result
    }
  end
end
pool.shutdown
puts "DECRYPTED: " + results.join
finish= Time.now
sort_sessionfile(file)
puts sprintf("DURATION: %0.02f seconds", (finish - start) % 60)