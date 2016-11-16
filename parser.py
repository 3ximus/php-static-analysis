#!/usr/bin/python2

import sys, os
import re


# -------- PATTERNS --------

class Pattern:
	'''Receives the name of the vuln and represents a pattern with entries:

		str vuln_name,
		list entry_points,
		list sanitization_functions,
		list sensitive_sinks,
	'''

	def __init__(self, vuln_name):
		self.vuln_name = vuln_name # string
		self.entry_points = [] # list of strings
		self.sanitization_functions = [] # list of strings
		self.sensitive_sinks = [] # list of strings

	def __repr__(self):
		return "Pattern: \"%s\"\nEntryPoints: %s\nSanitization functions: %s\nSensitive sinks: %s" % (self.vuln_name, self.entry_points, self.sanitization_functions, self.sensitive_sinks)

	def addEntry(self, mylist, entry):
		'''Add pattern entry (either a string or a list of strings) to a given type'''
		if isinstance(entry, list): mylist.extend(entry)
		else: mylist.append(entry)

class PatternCollection:
	def __init__(self, path):
		self.patterns = [] # will contain instances of Pattern

		if not os.path.exists(path):
			print "Unexistent patterns file \"%s\"" % path
			sys.exit(-1)
		with open(path, 'r') as fp:
			self.parsePatternsFile(fp)

	def __getitem__(self, key):
		self.patterns.__getitem__()

	def parsePatternsFile(self, fp):
		lines = fp.readlines()
		for i in range(0,len(lines), 5): # accounts for space between patterns
			new_pattern = Pattern(lines[i].strip('\n'))
			new_pattern.addEntry(new_pattern.entry_points, lines[i+1].strip('\n').split(','))
			new_pattern.addEntry(new_pattern.sanitization_functions, lines[i+2].strip('\n').split(','))
			new_pattern.addEntry(new_pattern.sensitive_sinks, lines[i+3].strip('\n').split(','))
			self.patterns.append(new_pattern)


# -------- PARSER --------

class PHPParser:
	'''Parse PHP into a sort of tree marking unsafe variables that come from user input'''

	# PHP stuff
	COMMENT = r'/\*(.|\n)*?\*/ | //([^?%\n]|[?%](?!>))*\n? | \#([^?%\n]|[?%](?!>))*\n?'
	PHP_OPENTAG = r'<[?%]((php[ \t\r\n]?)|=)?'
	PHP_CLOSETAG = r'[?%]>\r?\n?'
	INLINE_HTML = r'([^<]|<(?![?%]))+'
	PHP_STRING = r'[A-Za-z_][\w_]*'
	PHP_VARIABLE = r'\$[A-Za-z_][\w_]*'
	PHP_QUOTED_VARIABLE = r'\$[A-Za-z_][\w_]*'

	def __init__(self, path):
		self.nodeTree = [] # will contain instances of VarNode

		if not os.path.exists(path):
			print "Unexistent php file \"%s\"" % path
			sys.exit(-1)
		with open(path, 'r') as fp:
			self.parsePHPFile(fp)

	def parsePHPFile(self, fp):
		re.compile
		for lineno, line in enumerate(fp):



# -------- PARSER NODES --------

class AssocNode:
	def __init__(self, left, right):
		self.left_node = left
		self.right_node = right

class VarNode:
	def __init__(self, name, lineno, safe=False):
		self.name = name
		self.lineno = lineno
		self.safe

