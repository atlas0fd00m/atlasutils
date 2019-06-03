#!/usr/bin/python

#  toy "ROT13" en/decryptor

import sys

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

def rotN(text, ROTNUM):
    global a,b
    b = a[ROTNUM:26] + a[:ROTNUM] + a[26+ROTNUM:] + a[26:ROTNUM+26]
	output = ""
	for i in range(0,len(text)):
		index = a.find(text[i])
		if index > -1:
			output += b[index]
		else:
			output += text[i]
	return output


