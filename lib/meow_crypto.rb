#!/usr/bin/ruby
# Crypto Challenge:  http://cryptopals.com/

# requires
require './crypto.rb'
require 'colorize'

# Globals
$DEBUG = true
$SLOW = false 


# Matasano Crypto Challenges
# Set 1
# 1. Convert hex to base64 
puts "----------------------------------------------------------------------"
puts ">> crypto challenge :: Set: 1 :: Challenge: 1 "
puts "----------------------------------------------------------------------\n"

$in1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f6' +
  '9736f6e6f7573206d757368726f6f6d'
$ex1 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

base64 = bin_to_base64(hex_to_bin($in1))
puts "base64: \n#{base64} " 
(base64.eql? $ex1)?(puts "Correct: TRUE".green):(puts "Correct: FALSE".red)


# 2. Fixed XOR
puts "\n----------------------------------------------------------------------"
puts ">> crypto challenge :: Set: 1 :: Challenge: 2 "
puts "----------------------------------------------------------------------\n"

$inA = '1c0111001f010100061a024b53535009181c'
$inB = '686974207468652062756c6c277320657965'
$ex2 = '746865206b696420646f6e277420706c6179'

xor = fixed_xor_hex($inA, $inB)
puts "XOR: \n#{xor}" 
(xor.eql? $ex2)?(puts "Correct: TRUE".green):(puts "Correct: FALSE".red)


# 3. Single-byte XOR cipher
puts "\n----------------------------------------------------------------------"
puts ">> crypto challenge :: Set: 1 :: Challenge: 3 "
puts "----------------------------------------------------------------------\n"

$in3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

def do_xor_crack(a,key)
  aa = str_to_intArray(a)
  i = 0
  xor = ''
  while i < aa.size do
    xor << ( aa[i] ^ key ).to_s(16)
  i += 1
  end
return xor
end

def decrypt_xor(h)
  bf = Array.new
  result = Hash.new
  for i in 0..255
    bf[i] = [do_xor_crack(h, i )].pack('H*')
    result[i] = freq_to_int(bf[i])

#    puts "#{freq_to_int(freq_anal(bf[i]))}: " + bf[i]
#    puts "#{i}: " + bf[i]
#    puts "xor #{i}: " + [do_xor_crack($input3, i )].pack('H*')
  end
  puts "-= Results for XOR decipher analysis =-"
  result.sort_by {|k,v| v}.reverse[0..4].each do |k,v|
    puts "Key:#{k.chr} | Score: #{v}  |  Text: #{bf[k]}"
  end
end

def freq_to_int(msg)
  hash = freq_anal(msg)
  score = 0
  hash.each do |k,v|
    score = case k
      when ('e' or 't' or 'a' or 'o' or 'i') then score += 3 * v
      else score += v
    end
  end

  score += 10 * (msg.split(' ') & $KEYWORDS).length
#  score += 10 if $keywords.any? {|w| msg[w]}
return score
end

def freq_anal(msg)
  h = Hash.new 0
#  s = msg.gsub(/[\W_]+/, '')
  s = msg.gsub(/[^A-Za-z]+/, '').downcase

  unless s.length == 0
    s.split("").each do |c|
      h[c.chr] += 1 
    end
  end

return h
end

decrypt_xor($in3)


puts "\n----------------------------------------------------------------------"
puts ">> crypto challenge :: Set: 1 :: Challenge: 4 "
puts "----------------------------------------------------------------------\n"

$eval_hash = Hash.new

def xor_analyze(msg)
  bf = Array.new
  ret = Array.new
  result = Hash.new

  for i in 0..255
    bf[i] = [do_xor_crack(msg, i )].pack('H*')
    result[i] = freq_to_int(bf[i])
    
  end
  ret = result.sort_by {|k,v| v}.reverse[0]

return ret[0], ret[1], bf[ret[0]] 
end

def find_xor_string
  result = Hash.new
  values = Array.new
  line_num = 0

  File.open('./4.txt').each do |line|
    score = 0
    key = 0
    msg = ''     
    key, score, msg = xor_analyze(line)
    $eval_hash[score] = [line_num, key, msg]
    line_num += 1
  end
  puts "-= Results for XOR-File decipher analysis =-"
  $eval_hash.sort_by {|k,v| k}.reverse[0..4].each do |k,v|  
    puts "Score: #{k}  Line: #{v[0]}  Key: #{v[1]}  |  Text: #{v[2]}"   
  end

=begin
  result.sort_by {|k,v| v}.reverse[0..19].each do |k,v|
    puts "#{k}:  Score: #{v[0]}  |  Text: #{bf[v[0]]} "
  end
=end
end

puts "not run! (set parameter $SLOW == true)" if $SLOW == false
find_xor_string() if $SLOW == true


puts "\n----------------------------------------------------------------------"
puts ">> crypto challenge :: Set: 1 :: Challenge: 5 "
puts "----------------------------------------------------------------------\n"

$in5 = "Burning 'em, if you ain't quick and nimble\n" +
  "I go crazy when I hear a cymbal"

$in51 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242" +
  "72765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028316528632630" +
  "2e27282f"

def decrypt_xor_string(msg,key)
  aa = str_to_intArray(msg_to_hex(msg))
#  aa[42] = 10
  hex_key = msg_to_hex(key.ljust(aa.length, key))
  full_key = str_to_intArray(hex_key)
  i = 0
  xor = ''
  while i < aa.size do
    xor << ( aa[i] ^ full_key[i] ).to_s(16).rjust(2, '0')
#    puts "#{i}  aa= #{aa[i]}  val= #{( aa[i] ^ full_key[i] ).to_s(16).rjust(2, '0')}  str= #{msg[i..i]} xor= #{full_key[i]} "
    
  i += 1
  end
return xor
end

string = decrypt_xor_string($in5,"ICE")
puts "string: \n#{string}" 
(string.eql? $in51)?(puts "Correct: TRUE".green):(puts "Correct: FALSE".red)

# puts "Identical: #{ string.eql? $in51}"


puts "\n----------------------------------------------------------------------"
puts ">> crypto challenge :: Set: 1 :: Challenge: 6 "
puts "----------------------------------------------------------------------\n"

keymin = 2
keymax = 40


## Debug
if $SLOW == true
  $in6a = "this is a test"
  $in6b = "wokka wokka!!!"
  
  puts "Hamming distance test: "
  puts str_to_binStr($in6a)
  puts str_to_binStr($in6b)
  
  sbin1 = str_to_binStr($in6a)
  sbin2 = str_to_binStr($in6b)
  
  puts iHammingDist
  puts hammingDistance(sbin1,sbin2)
end

file = File.open("./6.txt", "rb")
content = file.read

# remove NewLines and write to new file
sHex = str_to_hex(content.gsub(/\n/,""))
File.open("./6_hex.txt", "w") { |file| file.write(sHex) }

hammingHash = Hash.new

for i in keymin..keymax
  iHam1 = hammingDistance(str_to_binStr(sHex[0,i]),str_to_binStr(sHex[i,i]))
  iHam2 = hammingDistance(str_to_binStr(sHex[i,i]),str_to_binStr(sHex[2*i,i]))
  iHam3 = hammingDistance(str_to_binStr(sHex[2*i,i]),str_to_binStr(sHex[3*i,i]))
  iHam4 = hammingDistance(str_to_binStr(sHex[3*i,i]),str_to_binStr(sHex[4*i,i]))
  hammingHash[i] = (iHam1 + iHam2 + iHam3 + iHam4) / (4*i)
  
end
puts hammingHash

keys = hammingHash.select {|k,v| v == hammingHash.values.max }.keys
puts "----"
puts keys

puts new_histogram









