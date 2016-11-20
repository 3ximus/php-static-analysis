#!/usr/bin/python2

'''
This module has :
	- Pattern defining a set of entry points, sensitive sinks and sanitization functions
	- Pattern colletion that loads Patterns from a file and stores them in a list
	- PHPParser that parses a file and produces a VariableFlowGraph that chains entry points
		to either sensitive sinks or sanitization functions
	- VariableFlowGraph that contains a chan of nodes. The nodes themselves maintain the links given
		when added to the graph, the graph itself only maintains a list of the border nodes
'''

import os
import re
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

UNIQ_ID = 0
def get_nex_int():
	'''Get a new unique int. Not thread safe'''
	global UNIQ_ID
	UNIQ_ID += 1
	return UNIQ_ID

# -------- PATTERNS --------

class Pattern:
	'''Receives the name of the vuln and represents a pattern with entries:

		- str - vuln_name,
		- list - entry_points,
		- list - sanitization_functions,
		- list - sensitive_sinks,
	'''

	ENTRY_POINT, SANITIZATION_FUNCTION, SENSITIVE_SINK = range(3)

	def __init__(self, vuln_name):
		self.vuln_name = vuln_name # string
		self.entry_points = [] # list of strings
		self.sanitization_functions = [] # list of strings
		self.sensitive_sinks = [] # list of strings
		self.match_type=None

	def get_type(self): return self.match_type
	def set_match_type(self, value): self.match_type=value

	def __repr__(self):
		return "%sPattern:%s \"%s\"\n%sEntryPoints:%s %s\n   \
				\r%sSanitization functions:%s %s\n%sSensitive sinks:%s %s" % \
				(COLOR.CYAN, COLOR.NO_COLOR, self.vuln_name,
				COLOR.CYAN, COLOR.NO_COLOR, self.entry_points,
				COLOR.CYAN, COLOR.NO_COLOR, self.sanitization_functions,
				COLOR.CYAN, COLOR.NO_COLOR, self.sensitive_sinks)

	def add_entry(self, mylist, entry):
		'''Add pattern entry (either a string or a list of strings) to a given type'''
		if len(entry) == 1 and entry[0] == "":
			return

		if isinstance(entry, list): mylist.extend(entry)
		else: mylist.append(entry)

	def apply_pattern(self, string):
		'''Applies pattern to a string and returns its match name and match type'''
		for ss in self.sensitive_sinks:
			if ss in string: return ss, self.SENSITIVE_SINK
		for ep in self.entry_points:
			if ep in string: return ep, self.ENTRY_POINT
		for sf in self.sanitization_functions:
			if sf in string: return sf, self.SANITIZATION_FUNCTION
		return None, None


class PatternCollection:
	'''Collection of patterns - added to self.patterns parsed from a given file'''
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
			new_pattern.add_entry(new_pattern.entry_points, lines[i+1].strip('\n').split(','))
			new_pattern.add_entry(new_pattern.sanitization_functions, lines[i+2].strip('\n').split(','))
			new_pattern.add_entry(new_pattern.sensitive_sinks, lines[i+3].strip('\n').split(','))
			self.patterns.append(new_pattern)


# -------- PARSER --------

class PHPParser:
	'''Parse PHP into a sort of tree marking unsafe variables that come from user input

	Receives a PHP file to parse and a Pattern instance
	'''

	# PHP stuff
	SINGLE_LINE_COMMENT = re.compile(r'\/\/.*\n|#.*\n')
	MULTI_LINE_COMMENT = re.compile(r'/\*((?:.|\n)*?)\*/')
	PHP_EMBEDDED_HTML = re.compile(r'<.*<[?%]php[ \s]?(.*)\?>.*>') # html code will be on group1
	PHP_STRING = re.compile(r'\".*\"')
	PHP_VARIABLE = re.compile(r'\$[A-Za-z_][\w_]*')
	VAR_ASSIGNMENT = re.compile(r'(\$[A-Za-z_][\w_]*)\s*=(?!=)\s*(.*)') # stores the variable in group1 and the right value in group2
	# this is not just a function call, it can also be a command
	PHP_FUNC_CALL = re.compile(r'[A-Za-z_][\w_]*\((.*)\)|[A-Za-z_][\w_]*\ (.*)') # arguments will be in group1

	def __init__(self, path, pattern, verbose_level=0):
		self.flow_graph = VariableFlowGraph()
		self.normalized_file = [] # contains the full snippet
		self.pattern = pattern # instance of Pattern
		self.processed_file = False
		self.is_vulnerable_snippet = False
		self.verbose = verbose_level
		if not self.pattern or not isinstance(self.pattern, Pattern):
			print "Invalid pattern given"
			sys.exit(-1)
		if not os.path.exists(path):
			print "Unexistent php file \"%s\"" % path
			sys.exit(-1)
		with open(path, 'r') as fp:
			self.normalize_php_file(fp)
		self.parse_php_file() # builds node graph
		self.set_vulnerable_status()

# -------- FILE PARSE METHOD --------

	def parse_php_file(self):
		'''Reades file creating nodes and adding them to the flowGraph'''
		for lineno, line in enumerate(self.normalized_file):
			line = line.strip(' \t\r\n')
			if line == "": continue

			if self.verbose == 2: print "%sParsing Line: %s%s" % (COLOR.BLUE, COLOR.NO_COLOR, line)

			match = self.VAR_ASSIGNMENT.search(line)
			if match:
				self.process_var_assignment(match, lineno)
				continue

			# process only pattern
			if self.process_pattern(line, lineno):
				continue

			# ignore everything else

	def normalize_php_file(self, fp):
		file_content = fp.read()
		file_content = re.sub(self.PHP_EMBEDDED_HTML, r'\g<1>', file_content)
		file_content = re.sub(self.SINGLE_LINE_COMMENT, '', file_content)
		file_content = re.sub(self.MULTI_LINE_COMMENT, '', file_content)
		self.normalized_file = [line.strip(' \t\r\n').replace('\n','') for line in re.split(r'[;\{\}]', file_content)]


# -------- PARSE METHODS --------

	def process_pattern(self, line, lineno, var_node=None):
		'''Process line with class pattern. Returns whether or not it matched sucessfully.'''
		match_name, match_type = self.pattern.apply_pattern(line) # apply pattern to the right value
		if match_name:
			if match_type == Pattern.ENTRY_POINT:
				return self.process_entry_point(match_name, lineno, var_node)
			else:
				return self.process_end_node(line, match_name, match_type, lineno, var_node=var_node)
		return None

	def process_var_assignment(self, match, lineno):
		'''Process assignment of a variable in PHP
			The right value of an assignment can be:
				- An Entry Point (adds it to the graph),
				- An EndNode ( sanitization function or sensitive sink),
				- A String,
				- Another Variable
		'''
		if self.verbose == 2: print "%s\tVarAssigned%s: %s" % (COLOR.ITALIC, COLOR.NO_COLOR,match.group(1))
		var_node = VarNode(match.group(1), lineno)  # matched var on the left value
		# ignore process_pattern output because assignment only matter if they are of an entry point
		if not self.process_pattern(match.group(2), lineno, var_node=var_node):
			# patterns didnt match, try string assignment
			string_match = self.PHP_STRING.search(match.group(2))
			if string_match:
				strNode = self.process_string(match.group(2), lineno)
				if strNode: self.flow_graph.add_node(var_node, strNode) # add assigned var with vars inside string as parent nodes
				else: self.flow_graph.remove_node(var_node) # remove assigned variable from graph since its content is not problematic anymore
			else:  # string didnt match, try variable to variable assignment
				var_match = self.PHP_VARIABLE.search(match.group(2))
				node_var = self.find_nodes_by_value(var_match.group(0)) if var_match else []
				if node_var != []:
					if self.verbose == 2: print "\t  -> %sVarToVar%s: %s" % (COLOR.ITALIC, COLOR.NO_COLOR,match.group(2))
					# NOTE node_var is list of found nodes (it can only be 1 because there is
					# only one var)
					self.flow_graph.add_node(var_node, node_var[0])

	def process_entry_point(self, name, lineno, var_node):
		'''Receives the var node from the Entry point assignment'''
		if self.verbose == 2: print "%s\t  -> EntryPoint: %s%s" % (COLOR.YELLOW, COLOR.NO_COLOR,name)
		entry_node = EntryNode(name, lineno)
		self.flow_graph.add_node(entry_node)
		if var_node:
			var_node.entryPoint = True
			self.flow_graph.add_node(var_node, entry_node)
		return entry_node

	def process_end_node(self, match, match_name, match_type, lineno, var_node=None):
		'''Process end nodes, adds itself to the graph'''
		func_match = self.PHP_FUNC_CALL.search(match) # not really needed but
		if not func_match:
			print "Failed to match a function call on end node. Meaning an unexpected sanitization or sensitive pattern was given."
			return
		arg_match = func_match.group(1) if func_match.group(1) else func_match.group(2)
		# check if args are a pattern
		pNode = self.process_pattern(arg_match, lineno)
		if pNode:
			parent_nodes = [pNode,]
		# check if args are a variable
		else:
			args = self.PHP_VARIABLE.findall(arg_match) # get all variables in the arguments
			parent_nodes = self.find_nodes_by_value(*args)

		# process to add nodes
		end_node = None
		if parent_nodes != [] and match_type == Pattern.SANITIZATION_FUNCTION:
			if self.verbose == 2: print "%s\tEndNode: %s%s" % (COLOR.GREEN, COLOR.NO_COLOR,match_name)
			end_node = EndNode(match_name, lineno, poisoned=False)
			self.flow_graph.add_node(end_node, *parent_nodes)
			if var_node:
				# since we are sanitizing to this variable we must remove it from the tree
				self.flow_graph.remove_node(var_node)
		elif parent_nodes != [] and match_type == Pattern.SENSITIVE_SINK:
			if self.verbose == 2: print "%s\tEndNode: %s%s" % (COLOR.RED, COLOR.NO_COLOR,match_name)
			end_node = EndNode(match_name, lineno, poisoned=True)
			self.flow_graph.add_node(end_node, *parent_nodes)
		if self.verbose == 2: print "\t  -> %sArgs%s: %s" % (COLOR.ITALIC, COLOR.NO_COLOR,arg_match)
		return end_node

	def process_string(self, match, lineno):
		'''Processes String nodes, if it has variables in it adds itself to the graph with the parents being the
			variables used and returns the node created, otherwise it wont do and return nothing
		'''
		if self.verbose == 2: print "\t%sString%s: %s" % (COLOR.ITALIC, COLOR.NO_COLOR,match)
		args = self.PHP_VARIABLE.findall(match) # get all variables in the arguments
		if self.verbose == 2: print "\t  -> %sUsedVars%s: %s" % (COLOR.ITALIC, COLOR.NO_COLOR,", ".join(args))
		parent_nodes = self.find_nodes_by_value(*args)
		if parent_nodes != []:
			strNode = StringNode(match, lineno)
			self.flow_graph.add_node(strNode, *parent_nodes)
			return strNode

# -------- OTHER METHODS --------

	def find_nodes_by_value(self, *names):
		'''Finds already defined var_nodes by their names'''
		return self.flow_graph.find_nodes_by_value(*names)

	def set_vulnerable_status(self):
		for end_node in self.flow_graph.end_nodes:
			if end_node.poisoned:
				self.is_vulnerable_snippet = True
				return

	def isVulnerable(self):
		return self.is_vulnerable_snippet

	def annotate_line(self, lineno, anotation, markInline=None, color=''):
		'''Inserts an anotation on a certain snippet line, markInline is a string to mark with color if given'''
		if markInline:
			self.normalized_file[lineno] = self.normalized_file[lineno].replace(
				markInline, color + markInline + COLOR.NO_COLOR)
		self.normalized_file[lineno] += " " + anotation

	def get_processed_file(self, inLineAnnotations=False):
		'''Returns processed file with annotations'''
		if not self.processed_file:
			for node in self.flow_graph.walk_top_down(self.flow_graph.end_nodes):
				if isinstance(node, EntryNode):
					self.annotate_line(node.lineno, COLOR.YELLOW + "<- Entry Point (%s)" % node.nid +
					                   COLOR.NO_COLOR, node.value if inLineAnnotations else None, color=COLOR.YELLOW)
				elif isinstance(node, EndNode) and node.poisoned:
					self.annotate_line(node.lineno, COLOR.RED + "<- Sensitive Sink (%s)" %
					                   node.nid + COLOR.NO_COLOR, node.value if inLineAnnotations else None, color=COLOR.RED)
				elif isinstance(node, EndNode) and not node.poisoned:
					self.annotate_line(node.lineno, COLOR.GREEN + "<- Sanitization Function (%s)" %
					                   node.nid + COLOR.NO_COLOR, node.value if inLineAnnotations else None, color=COLOR.GREEN)
			self.processed_file = True
		return "\n".join(self.normalized_file)

# ----------------------------------------


# -------- PARSER GRAPH --------

class VariableFlowGraph:
	r'''This class contains a variable content propagation graph

		This class will behave as demonstrated in the following php file example:

			$var1=$_GET['idn'];
			$var2=$_POST['sis'];
			$var3=$_COOKIE['ll'];
			$varx=$_POST['ss'];

			$vary="SELECT var1,nis,semester FROM nilai WHERE nis='$var1'GROUP BY semester";
			$varw="SELECT var1,nis,semester FROM nilai WHERE nis='$var2' AND ll='$var3' GROUP BY semester";

			$varz=mysql_query($vary,$var0);
			$v1=mysql_query($varw,$var0);
			$v2=mysql_query($varx,$var0);
			$test=mysql_real_escape_string($varx);
			$out=mysql_query($test,$var0);

		This would generate the following trees:

                           $var1             $var2     $var3      $varx
                              |                 \       /           |
                              |                  \     /            |
                              |                   \   /             |
                             str1                 str2           END_NODE
                              |                     |
                              |                     |
                            $vary                $varw
                            /   \                   |
                           /     \                  |
                          /       \              END_NODE
                     END_NODE   END_NODE

		The list self.end_nodes will always be the top nodes in the tree in this case in the end
			would contain all the end nodes

		A variable is only added to the node if its assigned from an entry point.
		And END_NODE is either a Sanitization function or a Sensitive Sink if its the latter the
			variable is marked as poisoned, in either case of END_NODES, no more nodes can be added
			to them (NOTE: even if there are huge chains it wont matter since the bug was already found)
	'''
	def __init__(self):
		self.end_nodes = [] # list of all the top nodes
		self.entry_nodes = [] # list of all the entry nodes
		self.node_references= {} # dictionary of node references, key is node.name

# -------- OUTPUT METHODS --------

	def __repr__(self, nodes=None, traceCount=0, span=None):
		'''Recurse __repr__ call, prints the tree structure, check it out, its pretty'''
		out = ''
		if nodes == None: # default values on first call
			nodes = self.end_nodes
			span = [] # cant set default value since list is persistent across calls
			out = "Legend: %s Entry Points %sSanitization Functions %sSensitive Sinks%s\n" % \
					(COLOR.YELLOW, COLOR.GREEN, COLOR.RED, COLOR.NO_COLOR)
		if len(nodes)!=1: span.append(traceCount)
		for i, node in enumerate(nodes):
			if len(nodes) == i+1 and traceCount in span: span.remove(traceCount)
			out += "\n%s%s%s%s%s%s" %  \
					(''.join([u'\u2502     ' if x in span else u'      ' for x in range(traceCount)]), # sets padding with tree branches
					u'\u2514\u2500\u2500 ' if len(nodes)==i+1 else u'\u251c\u2500\u2500 ', # set branch division simbol
					COLOR.RED if isinstance(node, EndNode) and node.poisoned else \
						(COLOR.GREEN if isinstance(node, EndNode) and not node.poisoned else \
							(COLOR.YELLOW if isinstance(node, EntryNode) else '')),
					node,
					COLOR.NO_COLOR,
					self.__repr__(node.prev, traceCount+1, span) if node.prev != [] else "")
		return out

# -------- NODES METHODS --------

	def add_node(self, node, *parentNodes):
		'''Adds node to the graph, its impossible to add a non VarNode without a parentNode'''
		if parentNodes == (None,): parentNodes = [] # normalize
		if not parentNodes and isinstance(node, EntryNode):
			self.entry_nodes.append(node)  # creates a new branch
			self.node_references.update({node.nid: node})
			return

		for pNode in parentNodes:  # if there arent any parent nodes this cycle wont run
			if not self.has_node(pNode):
				print "Ading node with unexistent parent. Shouldn\'t happen."
				continue # node doesnt exist in the tree
			if pNode in self.end_nodes:
				continue # cant add nodes after end_nodes
			pNode.next.append(node)
			node.prev.append(pNode)

		if node.prev != []:
			if isinstance(node, VarNode) and self.has_node(node):
				self.remove_node(self.node_references[node.nid]) # remove previous in order to add redefenition
			self.node_references.update({node.nid: node})
			if isinstance(node, EndNode):
				self.end_nodes.append(node)
				if node.poisoned: self.propagate_poison(node)

	def has_node(self, node):
		return node.nid in self.node_references

	def remove_node(self, node):
		if not self.has_node(node): return # nothing to do here
		for future in node.next:
			if len(future.prev) == 1:
				# assume that prev list on next node will always contain this node,
				# therefore if len == 1 it can be removed since we are the node holding it
				self.remove_node(future)
			else:  # otherwise only remove this node from its prev list
				future.prev.remove(node)
		for parent in node.prev:
			parent.next.remove(node)
		if node in self.entry_nodes:
			self.entry_nodes.remove(node)
		if node in self.end_nodes:
			self.end_nodes.remove(node)
		del(self.node_references[node.nid])

	def propagate_poison(self, node):
		'''Receives a node that originates the poison and spreads it contaminating all reachable VarNodes, <<<< this description xD'''
		for n in node.prev:
			if isinstance(n, VarNode):
				n.set_poisoned(True)
			self.propagate_poison(n)

	def walk_top_down(self, nodes):
		'''Iterate over this method to retrieved all the nodes in the tree one by one '''
		for n in nodes:
			if n: yield n
			for x in self.walk_top_down(n.prev):
				if x: yield x

	def walk_bottom_ip(self, nodes):
		'''Iterate over this method to retrieved all the nodes in the tree one by one '''
		for n in nodes:
			if n: yield n
			for x in self.walk_bottom_ip(n.next):
				if x: yield x

	def find_nodes_by_value(self, *names):
		'''Finds all nodes with given names

			NOTE that this function allows names not found in the nodes, so it will ignore undeclared variables
		'''
		found_nodes = []
		for key, node in self.node_references.iteritems():
			if isinstance(node, VarNode) and key in names:
				if node not in found_nodes: found_nodes.append(node)
		return found_nodes

# -------- PARSER NODES --------

class Node(object):
	def __init__(self, nid, value, lineno):
 		# tuple of previous and next nodes
		self.nid = nid
		self.lineno = lineno
		self.value = value
		self.next = []
		self.prev = []
	def __repr__(self):
		return "[ %s ]" % self.nid

class StringNode(Node):
	def __init__(self, value, lineno):
		super(StringNode, self).__init__("str%d" % get_nex_int(), value, lineno)
	def __repr__(self):
		return "[ %s ] - %s..." % (self.nid, self.value[:20])

class VarNode(Node):
	def __init__(self, value, lineno, entryPoint=False):
		super(VarNode, self).__init__(value, value, lineno)
		self.poisoned = None # if its content carries over to a Sensitive Sink
		self.entryPoint = entryPoint

	def set_poisoned(self, val):
		self.poisoned = val

class EndNode(Node):
	def __init__(self, value, lineno, poisoned):
		super(EndNode, self).__init__("end%d" % get_nex_int(), value, lineno)
		self.poisoned = poisoned
	def __repr__(self):
		return "[ %s ] - %s" % (self.nid, self.value)

class EntryNode(Node):
	def __init__(self, value, lineno):
		super(EntryNode, self).__init__("entry%d" % get_nex_int(), value, lineno)
	def __repr__(self):
		return "[ %s ]" % self.value

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
