#!/usr/bin/python2

import sys, os
import re
reload(sys)
sys.setdefaultencoding('utf-8')


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
		return "%sPattern:%s \"%s\"\n%sEntryPoints:%s %s\n   \
				\r%sSanitization functions:%s %s\n%sSensitive sinks:%s %s" % \
				(COLOR.CYAN, COLOR.NO_COLOR, self.vuln_name,
				COLOR.CYAN,COLOR.NO_COLOR, self.entry_points,
				COLOR.CYAN,COLOR.NO_COLOR, self.sanitization_functions,
				COLOR.CYAN,COLOR.NO_COLOR, self.sensitive_sinks)

	def addEntry(self, mylist, entry):
		'''Add pattern entry (either a string or a list of strings) to a given type'''
		if isinstance(entry, list): mylist.extend(entry)
		else: mylist.append(entry)

	def applyPattern(self, string):
		'''Applies pattern to a string and returns its match name and match type'''
		for ep in self.entry_points:
			if ep in string: return ep, self.ENTRY_POINT
		for ss in self.sensitive_sinks:
			if ss in string: return ss, self.SENSITIVE_SINK
		for sf in self.sanitization_functions:
			if sf in string: return sf, self.SANITIZATION_FUNCTION
		return None, None


class PatternCollection:
	def __init__(self, path):
		self.patterns = [] # will contain instances of Pattern

		if not os.path.exists(path):
			print "Unexistent patterns file \"%s\"" % path
			sys.exit(-1)
		with open(path, 'r') as fp:
			self.parsePatternsFile(fp)

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

	def __init__(self, path, pattern):
		self.flowGraph = VariableFlowGraph()
		self.loaded_snippet = [] # contains the full snippet
		self.pattern = pattern # instance of Pattern

		if not os.path.exists(path):
			print "Unexistent php file \"%s\"" % path
			sys.exit(-1)
		with open(path, 'r') as fp:
			self.parsePHPFile(fp) # builds node graph

# -------- FILE PARSE METHOD --------

	def parsePHPFile(self, fp):
		'''Reades file creating nodes and adding them to the flowGraph'''
		re.compile
		line = ""
		lineno=-1
		for original_lineno, templine in enumerate(fp):
			# concatenate and strip unwanted chars
			line = (line + " " + templine).strip(' \t\r\n')
			if line == "" or line[-1] != ';': # multiline cases
				continue
			else: line = line[:-1]
			self.loaded_snippet.append(line)
			lineno+=1

			# XXX Output
			print "%sParsing Line: %s%s" % (COLOR.BLUE, COLOR.NO_COLOR,line)

			# parse line
			if self.COMMENT.search(line):
				line = ""
				continue # ignore comments

			match = self.VAR_ASSIGNMENT.search(line)
			if match:
				self.processVarAssignment(match, lineno)
				line = ""
				continue

			# TODO process single entry points
			# TODO process single end nodes

			# TODO what else can it be

			match = self.PHP_VARIABLE.search(line)
			if match: print "UNHANDLED VAR" + match.group(0)

			# ignore everything else


# -------- PARSE METHODS --------

	def processPattern(self, line):
		# TODO encapsulate pattern matching here ( done in self.processVarAssignment )
		pass

	def processVarAssignment(self, match, lineno):
		'''Process assignment of a variable in PHP
			The right value of an assignment can be:
				An Entry Point (adds it to the graph),
				An EndNode ( sanitization function or sensitive sink),
				A String,
		'''
		# XXX Output
		print "%s\tVarAssigned%s: %s" % (COLOR.ITALIC, COLOR.NO_COLOR,match.group(1))
		var_node = VarNode(match.group(1), lineno) # matched var on the left value
		matchName, matchType = self.pattern.applyPattern(match.group(2)) # apply pattern to the right value
		if matchName:
			if matchType == Pattern.ENTRY_POINT:
				# XXX Output
				print "%s\t  -> EntryPoint: %s%s" % (COLOR.YELLOW, COLOR.NO_COLOR,matchName)
				var_node.entryPoint = True
				self.flowGraph.addNode(var_node)
			else:
				self.processEndNone(match.group(2), matchName, matchType, lineno)
		else : # patterns didnt match, try string assignment
			string_match = self.PHP_STRING.search(match.group(2))
			if string_match:
				strNode = self.processString(match.group(2), lineno)
				if StringNode:
					self.flowGraph.addNode(var_node, strNode)
			else: # string didnt match, try variable to variable assignment
				var_match = self.PHP_VARIABLE.search(match.group(2))
				node_var = self.findVarNodes(var_match.group(0))
				if node_var != []:
					# XXX Output
					print "\t  -> %sVarToVar%s: %s" % (COLOR.ITALIC, COLOR.NO_COLOR,match.group(2))
					self.flowGraph.addNode(var_node, node_var[0]) #node_var is list of found nodes (it can only be 1 because there is only one var)
		# TODO add any other option here?

	def processEndNone(self, match, matchName, matchType, lineno):
		'''Process end nodes, adds itself to the graph'''
		func_match = self.PHP_FUNC_CALL.search(match) # not really needed but
		if not func_match:
			# XXX Output
			print "Failed to match a function call on end node. Meaning an unexpected sanitization or sensitive pattern was given."
			return
		args = self.PHP_VARIABLE.findall(func_match.group(1)) # get all variables in the arguments
		parent_nodes = self.findVarNodes(*args)

		if parent_nodes != [] and matchType == Pattern.SANITIZATION_FUNCTION:
			# XXX Output
			print "%s\tEndNode: %s%s" % (COLOR.GREEN, COLOR.NO_COLOR,matchName)
			self.flowGraph.addNode(EndNode(matchName, lineno, poisoned=False), *parent_nodes)
		elif parent_nodes != [] and matchType == Pattern.SENSITIVE_SINK:
			# XXX Output
			print "%s\tEndNode: %s%s" % (COLOR.RED, COLOR.NO_COLOR,matchName)
			self.flowGraph.addNode(EndNode(matchName, lineno, poisoned=True), *parent_nodes)
		# XXX Output
		print "\t  -> %sArgs%s: %s" % (COLOR.ITALIC, COLOR.NO_COLOR,", ".join(args))


# TODO FIXME this is likely useless, maybe we should just link a variable
# found in a string to the variable the string was assigned to
	def processString(self, match, lineno):
		'''Processes String nodes, if it has variables in it adds itself to the graph with the parents being the
			variables used and returns the node created, otherwise it wont do and return nothing
		'''
		# XXX Output
		print "\t%sString%s: %s" % (COLOR.ITALIC, COLOR.NO_COLOR,match)
		args = self.PHP_VARIABLE.findall(match) # get all variables in the arguments
		# XXX Output
		print "\t  -> %sUsedVars%s: %s" % (COLOR.ITALIC, COLOR.NO_COLOR,", ".join(args))
		parent_nodes = self.findVarNodes(*args)
		if parent_nodes != []:
			strNode = StringNode(match, lineno)
			self.flowGraph.addNode(strNode, *parent_nodes)
			return strNode

# -------- OTHER METHODS --------

	def findVarNodes(self, *names):
		'''Finds already defined varNodes by their names'''
		return self.flowGraph.findVarNodes(*names)

	def annotateLine(self, lineno, anotation, markInlineType=False):
		'''Inserts an anotation on a certain snippet line, markInlineType is a boolean used to do inline annotations'''
		if markInlineType:
			# TODO maybe move all this crap to the self.processPattern method, depends on the implementation
			matchName, matchType = self.pattern.applyPattern(self.loaded_snippet[lineno])
			if matchType == Pattern.ENTRY_POINT:
				self.loaded_snippet[lineno] = self.loaded_snippet[lineno].replace(
					matchName, COLOR.YELLOW + matchName + COLOR.NO_COLOR)
			if matchType == Pattern.SANITIZATION_FUNCTION:
				self.loaded_snippet[lineno] = self.loaded_snippet[lineno].replace(
					matchName, COLOR.GREEN + matchName + COLOR.NO_COLOR)
			if matchType == Pattern.SENSITIVE_SINK:
				self.loaded_snippet[lineno] = self.loaded_snippet[lineno].replace(
					matchName, COLOR.RED + matchName + COLOR.NO_COLOR)
		self.loaded_snippet[lineno] += " " + anotation

	def getProcessedFile(self, inLineAnnotations=False):
		'''Returns processed file with annotations'''
# FIXME this is can only be called once... make a backup of the lines and revert after processing or something
		for node in self.flowGraph.walkOverMe(self.flowGraph.top_list):
			if isinstance(node, VarNode) and node.entryPoint:
				self.annotateLine(node.lineno, COLOR.YELLOW+"<- Entry Point"+COLOR.NO_COLOR, inLineAnnotations)
			elif isinstance(node, EndNode) and node.poisoned:
				self.annotateLine(node.lineno, COLOR.RED+"<- Sensitive Sink"+COLOR.NO_COLOR, inLineAnnotations)
			elif isinstance(node, EndNode) and not node.poisoned:
				self.annotateLine(node.lineno, COLOR.GREEN+"<- Sanitization Function"+COLOR.NO_COLOR, inLineAnnotations)

		return "\n".join(self.loaded_snippet)


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

		The list self.top_list will always be the top nodes in the tree in this case in the end
			would contain all the end nodes

		A variable is only added to the node if its assigned from an entry point.
		And END_NODE is either a Sanitization function or a Sensitive Sink if its the latter the
			variable is marked as poisoned, in either case of END_NODES, no more nodes can be added
			to them (NOTE: even if there are huge chains it wont matter since the bug was already found)
	'''
	def __init__(self):
		self.top_list = []

# -------- OUTPUT METHODS --------

	def __repr__(self):
		out = "Legend: %sVariable from Entry Points %sPoisoned Variable%s\n\t%sSanitization Functions %sSensitive Sinks%s\n" % \
				(COLOR.YELLOW, COLOR.UNDERLINE_BACK+COLOR.YELLOW, COLOR.NO_COLOR, COLOR.GREEN, COLOR.RED, COLOR.NO_COLOR)
		out += self._internal__repr__(self.top_list, 0, [])
		return out

	def _internal__repr__(self, nodes, traceCount, span):
		tempOut = ""
		if len(nodes)!=1: span.append(traceCount)
		for i, node in enumerate(nodes):
			if len(nodes) == i+1 and traceCount in span: span.remove(traceCount)
			tempOut += "\n%s%s%s%s%s%s%s" % (''.join(map(lambda x: u'\u2502     ' if x in span else u'      ', range(traceCount))),
									u'\u2514\u2500\u2500 ' if len(nodes)==i+1 else u'\u251c\u2500\u2500 ',
									COLOR.UNDERLINE_BACK if isinstance(node, VarNode) and node.entryPoint and node.poisoned else '',
									COLOR.RED if isinstance(node, EndNode) and node.poisoned else \
										(COLOR.GREEN if isinstance(node, EndNode) and not node.poisoned else \
											(COLOR.YELLOW if isinstance(node, VarNode) and node.entryPoint else '')),
									node.name,
									COLOR.NO_COLOR,
									self._internal__repr__(node.prev, traceCount+1, span) if node.prev != [] else "")
		return tempOut

# -------- NODES METHODS --------

	def addNode(self, node, *parentNodes):
		'''Adds node to the graph, its impossible to add a non VarNode without a parentNode'''
		if not parentNodes and isinstance(node, VarNode):
			self.top_list.append(node)
		elif parentNodes:
			for pNode in parentNodes:
				if not pNode in self.top_list:
					print "This shouldnt happen"
					return # FIXME MAYBE?
				if not self.tryDelete(pNode):
				 # if parent node is a Sanitization function (EndNode not poisoned) it cant
				 # be removed nor followed by more nodes
					continue
				pNode.next.append(node) # all the parent Nodes will point to the new node as the next
				node.prev.append(pNode)

			# if there are previous nodes (it wasnt added after a Sanitization
			# function) add node to flow list
			if node.prev != []:
				self.top_list.append(node)

				if isinstance(node, EndNode) and node.poisoned:
					self.propagatePoison(node)

	def tryDelete(self, node):
		'''Doesnt delete a node if its an EnlNode,
			in turn preventing the main algorithm from adding new nodes after this
		'''
		if isinstance(node, EndNode):
			return False
		else:
			self.top_list.remove(node)
			return True

	def propagatePoison(self, node):
		'''Receives a node that originates the poison and spreads it contaminating all reachable VarNodes, <<<< this description xD'''
		for n in node.prev:
			if isinstance(n, VarNode):
				n.poisoned = True
			self.propagatePoison(n)

	def walkOverMe(self, nodes):
		'''Iterate over this method to retrieved all the nodes in the tree one by one'''
		for n in nodes:
			yield n
			for x in self.walkOverMe(n.prev):
				yield x

	def findVarNodes(self, *names): # TODO use the walk over me instead of the recursive self._internalFindVarNodes
		'''Finds all nodes with given names
			NOTE that this function allows names not found in the nodes, so it will ignore undeclared variables
		'''
		found_nodes = []
		self._internalFindVarNodes(self.top_list, found_nodes, *names)
		return found_nodes

	def _internalFindVarNodes(self, nodes, found_nodes, *names):
		'''Recursive search for all variable nodes with name in the given names'''
		for node in nodes:
			if isinstance(node, VarNode) and node.name in names:
				if node not in found_nodes:
					found_nodes.append(node)
			if node.prev:
				self._internalFindVarNodes(node.prev, found_nodes, *names)


# -------- PARSER NODES --------

class Node(object):
	def __init__(self, name, lineno):
 		# tuple of previous and next nodes
		self.name = name
		self.lineno = lineno
		self.next = []
		self.prev = []

class StringNode(Node):
	def __init__(self, name, lineno):
		super(StringNode, self).__init__(name, lineno)

class VarNode(Node):
	def __init__(self, name, lineno, entryPoint=False):
		super(VarNode, self).__init__(name, lineno)
		self.poisoned = False # if its content carries over to a Sensitive Sink
		self.entryPoint = entryPoint

	def setPoisoned(self, value=True):
		self.poisoned = value

class EndNode(Node):
	def __init__(self, name, lineno, poisoned):
		super(EndNode, self).__init__(name, lineno)
		self.poisoned = poisoned

# -------- PRETTY THINGS :) --------

class COLOR:
	RED = "\033[31m"
	GREEN = "\033[32m"
	YELLOW = "\033[33m"
	BLUE = "\033[34m"
	PURPLE = "\033[35m"
	CYAN = "\033[36m"
	UNDERLINE_BACK = "\033[4;40m"
	ITALIC = "\033[3;29m"
	NO_COLOR = "\033[0m"
