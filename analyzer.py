#!/usr/bin/python2

import os, sys
import argparse
import PHPParser

PATTERNS_PATH = "patterns.txt"

# -------- MAIN --------

# Check received arguments
if __name__ == '__main__':
	op = argparse.ArgumentParser(description="PHP static analysis tool")
	op.add_argument('files', metavar='file', nargs='*', help='PHP files to be parsed')
	op.add_argument('-p', '--pattern-file', default=PATTERNS_PATH,  dest='pattern_file',
	                help='select patterns file to read patterns from, default is \'%(default)s\'')
	op.add_argument('-n', '--pattern-number', default=-1, type=int,
	                dest='pattern_number', help='select pattern to use by number of read patterns')
	op.add_argument('-v', '--verbose', nargs='?', default=0, type=int,
	              dest='verbose', help='show parsing output with given logging level, default is %(default)s')
	op.add_argument('-l', '--list', action='store_true',
	              dest='list', help='display list of patterns available')
	args = op.parse_args()

	pCollection = PHPParser.PatternCollection(args.pattern_file)
	if (args.list):
		for i, p in enumerate(pCollection.patterns):
			print i, p, '\n'
		sys.exit(0)

	if args.verbose == None: args.verbose = 1 # fix a bug in argparse

	# Read slice file
	files_to_parse = args.files
	if files_to_parse == []:
		print "No files were given"
		sys.exit(0)

	for f in files_to_parse:
		if os.path.exists(f) == False:
			print "\nSlice file path given (\"%s\") does not exist.\n" % f
			continue


		vuln_file = False
		print "\nParsing File: %s%s%s" % (PHPParser.COLOR.PURPLE, f, PHPParser.COLOR.NO_COLOR)
		for i, p in enumerate([None if args.pattern_number != -1 and i != args.pattern_number else p for i, p in enumerate(pCollection.patterns)]):
			if not p: continue
			if args.verbose == 2: print "Using Pattern: %d - %s" % (i, p.vuln_name)
			parser = PHPParser.PHPParser(f, p, verbose_level=args.verbose)

			if parser.isVulnerable():
				vuln_file = True
				if args.verbose:
					print "\nParse Tree:"
					print parser.flow_graph
				print "\n ----- > %s is vulnerable to: %s%s%s < -----\n" % (f,PHPParser.COLOR.ITALIC + PHPParser.COLOR.RED, p.vuln_name, PHPParser.COLOR.ITALIC + PHPParser.COLOR.NO_COLOR)
				print parser.get_processed_file(inLineAnnotations=True)

		if not vuln_file:
			print "\n ----- > %s%s is not vulnerable%s < -----\n" % (PHPParser.COLOR.GREEN, f, PHPParser.COLOR.NO_COLOR)

