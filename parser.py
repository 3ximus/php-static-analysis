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

	ENTRY_POINT, SANITIZATION_FUNCTION, SENSITIVE_SINK = range(3)

	def __init__(self, vuln_name):
		self.vuln_name = vuln_name # string
		self.entry_points = [] # list of strings
		self.sanitization_functions = [] # list of strings
		self.sensitive_sinks = [] # list of strings
		self.matchType=None

	def getType(self): return self.matchType
	def setMatchType(self, value): self.matchType=value

	def __repr__(self):
		return "Pattern: \"%s\"\nEntryPoints: %s\nSanitization functions: %s\nSensitive sinks: %s" % (self.vuln_name, self.entry_points, self.sanitization_functions, self.sensitive_sinks)

	def addEntry(self, mylist, entry):
		'''Add pattern entry (either a string or a list of strings) to a given type'''
		if isinstance(entry, list): mylist.extend(entry)
		else: mylist.append(entry)

	def applyPattern(self, string):
		'''Applies pattern to a string and returns its match name and match type'''
		for ep in self.entry_points:
			if ep in string: return ep, self.ENTRY_POINT
		for sf in self.sanitization_functions:
			if sf in string: return sf, self.SANITIZATION_FUNCTION
		for ss in self.sensitive_sinks:
			if ss in string: return ss, self.SENSITIVE_SINK
		return None, None


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
	COMMENT = re.compile(r'/\*(.|\n)*?\*/ | //([^?%\n]|[?%](?!>))*\n? | \#([^?%\n]|[?%](?!>))*\n?') # untested
	PHP_OPENTAG = re.compile(r'<[?%]((php[ \t\r\n]?)|=)?')
	PHP_CLOSETAG = re.compile(r'[?%]>\r?\n?') # untested
	OPEN_HTML_TAG = re.compile(r'<(?![?%])')
	PHP_STRING = re.compile(r'\".*\"')
	PHP_VARIABLE = re.compile(r'\$[A-Za-z_][\w_]*')
	VAR_ASSIGNMENT = re.compile(r'(\$[A-Za-z_][\w_]*)\s*=(?!=)\s*(.*)') # stores the variable in group1 and the right value in group2
	PHP_FUNC_CALL = re.compile(r'[A-Za-z_][\w_]*\((.*)\)') # arguments will be in group1

	def __init__(self, path, patternsColllection):
		self.flowGraph = VariableFlowGraph()
		self.loaded_snippet = [] # contains the full snippet
		self.pattern_collection = patternsColllection # instance of a PatterCollection class
		self.current_pattern = None

		if not os.path.exists(path):
			print "Unexistent php file \"%s\"" % path
			sys.exit(-1)
		with open(path, 'r') as fp:
			for pattern in self.pattern_collection:
				self.current_pattern = pattern
				self.parsePHPFile(fp) # builds node graph

# -------- FILE PARSE METHOD --------

	def parsePHPFile(self, fp):
		'''Reades file creating nodes and adding them to the flowGraph'''
		re.compile
		line = ""
		for lineno, templine in enumerate(fp):
			# concatenate and strip unwanted chars
			line = line.join(" "+templine).strip(' \t\r\n')
			if line[-1] != ';': # multiline cases
				continue
			else: line = line[:-1]

			# parse line
			if self.COMMENT.search(line):
				continue # ignore comments

			match = self.VAR_ASSIGNMENT.search(line)
			if match:
				self.processVarAssignment(match, lineno)

			# process only entry points

			# process only end nodes

			# what else can it be, only end nodes??

			# ignore everything else
			match = self.PHP_VARIABLE.search(line)
			if match: print "UNHANDLED VAR" + match(0)


			self.loaded_snippet.append(line)
			line = ""

# -------- PARSE METHODS --------

	def processVarAssignment(self, match, lineno):
		'''Process assignment of a variable in PHP
			The right value of an assignment can be:
				An Entry Point
				An EndNode ( sanitization function or sensitive sink)
				A String
		'''
		var_node = VarNode(match.group(1), lineno) # matched var on the left value
		matchName, matchType = self.current_pattern.applyPattern(match.group(2)) # apply pattern to the right value
		if matchName and matchType:
			if matchType == Pattern.ENTRY_POINT:
				self.flowGraph.addNode(var_node)
			else:
				self.processEndNone(match.group(2), matchName, matchType, lineno)
		else : # patterns didnt match, try string assignment
			new_match = self.PHP_STRING.search(line)
			if new_match:
				self.processString(match.group(2), lineno)

		print COLOR.BLUE + match.group(0) + COLOR.NO_COLOUR
		print COLOR.RED + match.group(1) + COLOR.NO_COLOUR
		print COLOR.GREEN + match.group(2) + COLOR.NO_COLOUR

	def processEndNone(self, match, matchName, matchType, lineno):
		func_match = self.PHP_FUNC_CALL.search(match)
		if not func_match: print "Failed to match a function call on end node. Meaning an unexpected sanitization or sensitive pattern was given."
		args = self.PHP_VARIABLE.findall(func_match.group(1)) # get all variables in the arguments
		parent_nodes = self.findVarNodes(*args)

		if matchType == Pattern.SANITIZATION_FUNCTION:
			self.flowGraph.addNode(EndNode(matchName, lineno, poisoned=False)) # incomplete needs parent nodes
		elif matchType == Pattern.SENSITIVE_SINK:
			self.flowGraph.addNode(EndNode(matchName, lineno, poisoned=True)) # incomplete needs parent nodes

# -------- OTHER METHODS --------

	def findVarNode(self, name):
		'''Finds an already defined varNode by its name'''
		self.flowGraph.find

	def anotateLine(self, lineno, anotation):
		'''Inserts an anotation on a certain snippet line'''
		self.loaded_snippet[lineno].join(" "+anotation)


# ----------------------------------------


# -------- PARSER GRAPH --------

class VariableFlowGraph:
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

                           $id_nilai         $strl      $cook     $varx
                              |                 \       /           |
                              |                  \     /            |
                              |                   \   /             |
                             str1                 str2           END_NODE
                              |                     |
                              |                     |
                            $q_nilai              $xcont
                             /   \                  |
                            /     \                 |
                           /       \             END_NODE
                      END_NODE   END_NODE

		The list self.flow_list will always be the top nodes in the tree in this case in the end would contain all the end nodes

		A variable is only added to the node if its assigned from an entry point.
		And END_NODE is either a Sanitization function or a Sensitive Sink if its the latter the variable is marked as poisoned,
			in either case of END_NODES, no more nodes can be added to them (NOTE: even if there are huge chains it wont matter since the bug was already found)
	'''
	def __init__(self):
		self.flow_list = []

	def addNode(self, node, *parentNodes):
		'''Adds node to the graph, its impossible to add a non VarNode without a parentNode'''
		if not parentNode and isinstance(node, VarNode):
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
		if isinstance(node, EndNode):
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

class Node(object):
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

class COLOR:
	RED = "\033[31m"
	GREEN = "\033[32m"
	YELLOW = "\033[33m"
	BLUE = "\033[34m"
	PURPLE = "\033[35m"
	CYAN = "\033[36m"
	NO_COLOUR = "\033[0m"
