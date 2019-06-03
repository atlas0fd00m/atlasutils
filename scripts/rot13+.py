#!/usr/bin/python

#  toy rot13+... "rot13 + character location" so "s" (which rot's to "f") in the third char would be "h" and in the fourth char would be "i"
import sys
s = sys.argv[1]
p = 13
out=""
for i in s:
 nextchar = ord(i) + p
 if (nextchar > 124):
  nextchar -= 26
 out += chr(nextchar)
 p +=1

print out
