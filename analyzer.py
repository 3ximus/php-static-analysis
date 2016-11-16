#!/usr/bin/python2

import sys, os
from parser import PatternCollection, PHPParser


PATTERNS_PATH = "patterns.txt"

# -------- MAIN --------

# Check received arguments
if __name__ == '__main__':
	if len(sys.argv) != 2:
		print "Usage: ./analyzer.py <filePath>"
		sys.exit(-1)

	p = PatternCollection(PATTERNS_PATH)
	print "Loaded patterns:"
	for pattern in p.patterns:
		print "%s\n" % pattern

	# Read slice file
	slice_file_path = sys.argv[1]
	if os.path.exists(slice_file_path) == False:
		print "Slice file path given (\"" + slice_file_path + "\") does not exist."
		sys.exit(-1)

	slice_file = open(slice_file_path, "r")
	slice_lines = slice_file.readlines()

	for pattern in p.patterns:
		pass # TODO: do something to check if the slice_lines are vulnerable