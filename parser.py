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
	COMMENT = re.compile(r'/\*(.|\n)*?\*/ | //([^?%\n]|[?%](?!>))*\n? | \#([^?%\n]|[?%](?!>))*\n?')
	PHP_OPENTAG = re.compile(r'<[?%]((php[ \t\r\n]?)|=)?')
	PHP_CLOSETAG = re.compile(r'[?%]>\r?\n?')
	INLINE_HTML = re.compile(r'([^<]|<(?![?%]))+')
	PHP_STRING = re.compile(r'[A-Za-z_][\w_]*')
	PHP_VARIABLE = re.compile(r'\$[A-Za-z_][\w_]*')
	PHP_QUOTED_VARIABLE = re.compile(r'\$[A-Za-z_][\w_]*')

	def __init__(self, path):
		self.nodeGraph = VariableNodeGraph()
		self.loaded_snippet = [] # contains the full snippet

		if not os.path.exists(path):
			print "Unexistent php file \"%s\"" % path
			sys.exit(-1)
		with open(path, 'r') as fp:
			self.parsePHPFile(fp) # builds node graph

	def parsePHPFile(self, fp):
		re.compile
		line = ""
		for lineno, templine in enumerate(fp):
			if line.strip(' \n')[-1] != ';':
				line.join(templine) # multiline cases
				continue
			else: line = templine

			# parse line
			if self.COMMENT.search(line): continue # ignore comments
			elif self.PHP_VARIABLE.search(line): pass # TODO


			self.loaded_snippet.append(line)
			line = ""

# -------- PARSER GRAPH --------

class VariableNodeGraph:
	'''This class contains a variable content propagation graph

		This class will behave as demonstrated in the following php file example:

			$id_nilai=$_GET['idn'];
			$strl=$_POST['sis'];
			$cook=$_COOKIE['ll'];
			$varx=$_POST['ss'];

			$q_nilai="SELECT id_nilai,nis,semester FROM nilai WHERE nis='$id_nilai'GROUP BY semester";
			$xcont="SELECT id_nilai,nis,semester FROM nilai WHERE nis='$strl' AND ll='$cook' GROUP BY semester";

			$hasil=mysql_query($q_nilai,$koneksi);
			$v1=mysql_query($xcont,$koneksi);
			$v2=mysql_query($varx,$koneksi);
			$test=mysql_real_escaped_string($q_nilai);
			$out=mysql_query($test,$koneksi);

		This would generate the following trees:

			$id_nilai       $strl      $cook     $varx
			   	|               \       /           |
			   	|                \     /	        |
			   	|                 \   /             |
			  str1                str2           END_NODE
			   	|                   |
			   	|                   |
			 $q_nilai            $xcont
			   /   \                |
			  /     \               |
			 /       \           END_NODE
		 END_NODE   END_NODE

		The list self.flow_list will always be the top nodes in the tree in this case in the end would contain all the end nodes

		A variable is only added to the node if its assigned from an entry point.
		And END_NODE is either a Sanitization function or a Sensitive Sink if its the latter the variable is marked as poisoned, if its the former no more can be added after it (the variable wont be poisoned)
	'''
	def __init__(self):
		self.flow_list = []

	def addNode(self, node, *parentNodes):
		'''Adds node to the graph, its impossible to add a non VarNode without a parentNode'''
		if not parentNode and isinstance(node, VarNode): # cannot insert new node if
			self.flow_list.append(node)
		elif parentNodes:
			for pNode in parentNodes:
				if not pNode in self.flow_list:
					print "This shouldnt happen"
					return # FIXME MAYBE?
				if not self.tryDelete(pNode):
					continue # if parent node is a Sanitization function (EndNode not poisoned) it cant be removed nor followed by more nodes
				pNode.next.append(node) # all the parent Nodes will point to the new node as the next
				node.prev.apend(pNode)
			if node.prev != []: # if there are previous nodes (it wasnt added after a Sanitization function) add node to flow list
				self.flow_list.append(node)

				if isinstance(node, EndNode) and node.poisoned:
					self.propagatePoison(node)

	def tryDelete(self, node):
		if isinstance(node, EndNode) and not node.poisoned:
			return False
		else:
			self.flow_list.remove(node)
			return True

	def propagatePoison(self, node):
		for n in node.prev:
			if isinstance(VarNode):
				n.poisoned = True
			self.propagatePoison(n)


# -------- PARSER NODES --------

class Node:
	def __init__(self):
 		# tuple of previous and next nodes
		self.next = []
		self.prev = []

class StringNode(Node):
	def __init__(self, string):
		super(StringNode, self).__init__()
		self.string = string

class VarNode(Node):
	def __init__(self, name, lineno):
		super(VarNode, self).__init__()
		self.name = name # variable name
		self.lineno = lineno # line number of where it was defined
		self.poisoned = False # if its content carries over to a Sensitive Sink

	def setPoisoned(self, value=True):
		self.poisoned = value

class EndNode(Node):
	def __init__(self, name, lineno, poisoned):
		super(EndNode, self).__init__()
		self.name = name
		self.lineno = lineno
		self.poisoned = poisoned


