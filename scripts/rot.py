#!/usr/bin/python

# another toy rot toy for use with any char-replacement cipher

import sys

myROT = 13

if (len(sys.argv) > 1 and sys.argv[0] == '-r'):
  snothing = sys.argv.pop(0)
  myROT = sys.argv.pop(0)


a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#   Reversed Alphbet
#b = "zyxwvutsrqponmlkjihgfedcba"

#ROT13
b = "nopqrstuvwxyzabcdefghijklmNOPQRSTUBWXYZABCDEFGHIJKLM"

# Gil Bates 
#b = "ubcdefghijnlmkopqrstavwxyz"
#b = "abcedfgkijhlmnopqrsutvwxyz"

def crypto(text):
	output = ""
	for i in range(0,len(text)):
		index = a.find(text[i])
		if index > -1:
			output += b[index]
		else:
			output += text[i]
	return output
if len(sys.argv) > 1:
	ciphertext = sys.argv[1]
else:
	ciphertext = sys.stdin.read()

print(crypto(ciphertext))

