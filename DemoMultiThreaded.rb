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
require './Poracle'
require './Utilities'
require 'optparse'
require 'thread/pool'
require 'ostruct'

class Demo
  attr_reader :iv, :data, :blocksize,:newlinechars,:url,:starting_block
  NAME = "Demo"
  # This function should load @data, @iv, and @blocksize appropriately
  def initialize()
    @data = HTTParty.get("http://localhost:20222/encrypt").parsed_response
    # Parse 'data' here
    #@data = [@data].pack("H*")
    @data =  [@data].pack("H*").unpack('C*')
    @iv = nil
    @blocksize = 16
  end

  # This should make a decryption attempt and return true/false
  def attempt_decrypt(data)
    data= data.flatten.pack('C*').unpack("H*")
    result = HTTParty.get("http://localhost:20222/decrypt/#{data.join}").parsed_response
    # Match 'result' appropriately
    return result !~ /Fail/
  end

  # Optionally define a character set, with the most common characters first
  def character_set()
    charset=' eationsrlhdcumpfgybw.k:v-/,CT0SA;B#G2xI1PFWE)3(*M\'!LRDHN_"9UO54Vj87q$K6zJY%?Z+=@QX&|[]<>^{}'
    return charset.chars.to_a
  end
end

#Main Program
options =  Utilities.parse(ARGV)
verbose = options.verbose
file = options.file
skip_blocks=[]
sortfile =options.sortfile
threadsize =options.threadsize

if (sortfile)
  Utilities.sort_sessionfile(file)
  results= Utilities.parse_sessionfile(file)
  puts "DECRYPTED: " + results.join

  exit
end

# Read already decrypted block from last time and add them to skip_blocks
results= Utilities.parse_sessionfile(file)
if (!results.nil?)
  results.each_with_index do |val,i|
    if (!val.nil? and val!="\n")
    skip_blocks<<i
    end
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
  blocks= mod.data.each_slice(mod.blocksize).to_a
  blocks.each do |b|
    i = i + 1
    puts(">>> Block #{i}: #{b.pack("C*").unpack("H*")}")
  end
end

start = Time.now

# Specify pool size
pool = Thread.pool(threadsize)
blockcount=mod.data.length / mod.blocksize
results=Array.new(blockcount)

# Spawn new thread for each block
(blockcount ).step(1,-1) do |i|
  if (!skip_blocks.include?(i))
    pool.process {
      result=Poracle.decrypt(mod, mod.data, iv,  verbose, i, file)
      results[i]=result.pack('C*').force_encoding('utf-8')
    }
  end
end
pool.shutdown
puts "DECRYPTED: " + results.join
finish= Time.now
Utilities.sort_sessionfile(file)
puts sprintf("DURATION: %0.02f seconds", (finish - start) % 60)