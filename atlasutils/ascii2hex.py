#!/usr/bin/python
import sys

def ascii2hex(ascii):
	output = ""
	for x in range(len(ascii)):
		output += "%.02x"%ord(ascii[x])
	return output


def hex2ascii(inp):
    outputline = ""
    for i in range(len(inp)/2):
      outputline += chr(int(inp[(i*2):(i*2)+2],16))
    return outputline

def ascii2decimel(ascii):
	output = ""
	for x in range(len(ascii)):
		output += "%.02d"%ord(ascii[x])
	return output


def decimel2ascii(inp):
    outputline = ""
    for i in range(len(inp)/2):
      outputline += chr(int(inp[(i*2):(i*2)+2]))
    return outputline
