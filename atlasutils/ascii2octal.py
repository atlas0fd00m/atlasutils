#!/usr/bin/python
import sys

def ascii2octal(ascii):
	output = ""
	for x in range(len(ascii)):
		output += "%.03o"%ord(ascii[x])
	return output


def octal2ascii(inp):
    outputline = ""
    for i in range(len(inp)/3):
      outputline += chr(int(inp[(i*3):(i*3)+3],8))
    return outputline
