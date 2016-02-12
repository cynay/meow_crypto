#!/usr/bin/ruby
# Crypto Challenge:  http://cryptopals.com/

# Globals
$ALPHA_LOWER = ("abcdefghijklmonpqrstuvwxyz").split("")
$BASE64 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
  "+/").scan(/./)
$KEYWORDS = ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'I', 
  'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this', 
  'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or', 'an', 
  'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what', 'so', 'up', 
  'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me', 'when', 'make', 
  'can', 'like', 'time', 'no', 'just', 'him', 'know', 'take', 'people', 'into',
  'year', 'your', 'good', 'some', 'could', 'them', 'see', 'other', 'than', 
  'then', 'now', 'look', 'only', 'come', 'its', 'over', 'think', 'also', 
  'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first', 'well', 'way', 
  'even', 'new', 'want', 'because', 'any', 'these', 'give', 'day', 'most', 
  'us']
$HGRAM = Hash.new

# Simple convertions
#
#

# STRING to ..
# 5
def msg_to_hex(msg)
return msg.unpack('H*')[0]
end

# 2
def str_to_intArray(s)
return s.scan(/../).map { |i| i.hex.to_i }.to_a
end

def str_to_base64(s)
return [[s].pack('H*')].pack('m0')
end

def str_to_binStr(s)
return s.unpack("B*").to_s
end

# BASE64 to ..
#

def str_to_hex(s)
return s.unpack('m0').first.unpack('H*').first
end

# HEX to ..
# 1
def hex_to_bin(hex)
return hex.hex.to_s(2).rjust(hex.length * 4, '0')
end

def hex_to_hex0x(hex)
return hex.scan(/../).map { |x| '0x' + x }.join
end

def hex_to_bin2(h)
return  h.scan(/..../).map { |x| "%08b" % x.hex.to_i }.join
end

def hex_to_intArray(hex)
return hex.scan(/../).map { |i| i.hex.to_i }.to_a
end


# BINARY to ..
# 1
def bin_to_base64(bin)
return bin.scan(/....../).map { |x| $BASE64[x.to_i(2)] }.join
end  


# Histogram methods
#
#
def new_histogram()
for i in 0..25 
  $HGRAM[$ALPHA_LOWER[i]] = 0
end
return $HGRAM
end



# XOR methods
#
#
 
# 2
def fixed_xor_hex(a,b)
  aa = hex_to_intArray(a)
  ab = hex_to_intArray(b)
  xor = ''
  aa.each_with_index { |v, i| xor << ( v ^ ab[i] ).to_s(16) }
return xor
end

def do_xor_byte(a,b)
  aa = str_to_intArray(a)
  ab = str_to_intArray(b)
  i = 0
  xor = ''
  while i < aa.size do
    xor << ( aa[i] ^ ab[i] ).to_s(16)
  i += 1
  end
return xor
end

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

  score += 10 * (msg.split(' ') & $keywords).length
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
end

def decrypt_xor_string(msg,key)
  aa = str_to_intArray(msg_to_hex(msg))
  aa[42] = 10
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

# Special functions

def hammingDist(s1,s2)
  iHammingDist = 0
  for i in 1..sbin1.length
      if sbin1[i] != sbin2[i]
        iHammingDist += 1
      end
  end
  return iHammingDist
end


def hammingDistance(s1,s2)
  raise "ERROT: Hamming: Non equal lengths" if s1.length != s2.length
  (s1.chars.zip(s2.chars)).count {|l, r|l != r}
end
