#!/usr/bin/python2

import sys
import os.path

PATTERNS_PATH = "patterns.txt" 

# -------------
# ---CLASSES---
# -------------
class Pattern:
    def __init__(self, vuln_name, entry_points, sanitization_functions, sensitive_sinks):
        self.vuln_name = vuln_name # string
        self.entry_points = entry_points # list of strings
        self.sanitization_functions = sanitization_functions # list of strings
        self.sensitive_sinks = sensitive_sinks # list of strings
    
    def __repr__(self):
        return "Pattern \"" + self.vuln_name + "\":\nEntry_points = " + str(self.entry_points) + \
                "\nSanitization functions = " + str(self.sanitization_functions) + \
                "\nSensitive sinks = " + str(self.sensitive_sinks)


# ---------------
# ---FUNCTIONS---
# ---------------
# Read pattern file and load to some structure
def load_pattern_file():
    if os.path.exists(PATTERNS_PATH) == False:
        print "Patterns file at \"" + patternsPath + "\" not found."
        sys.exit(-1)
    
    patterns = []
    patterns_file = open(PATTERNS_PATH, "r")
    patterns_file_lines = patterns_file.readlines()
    patterns_len = len(patterns_file_lines)
    i = 0

    while i + 4 <= patterns_len:
        name = patterns_file_lines[i].replace("\n", "")
        entry_points = patterns_file_lines[i+1].replace("\n", "").split(",")
        sanitization_functions = patterns_file_lines[i+2].replace("\n", "").split(",")
        sensitive_sinks = patterns_file_lines[i+3].replace("\n", "").split(",")
        patterns += [Pattern(name, entry_points, sanitization_functions, sensitive_sinks)]
        i += 5 # counting with an empty line between patters
        
    return patterns


# ----------
# ---MAIN---
# ----------
# Check received arguments
print "Args received: ", str(sys.argv)
if len(sys.argv) != 2:
    print("Usage: ./analyzer.py <filePath>")
    sys.exit(-1)

# Read slice file
slice_file_path = sys.argv[1]
if os.path.exists(slice_file_path) == False:
    print "Slice file path given (\"" + slice_file_path + "\") does not exist."
    sys.exit(-1)

slice_file = open(slice_file_path, "r")
slice_lines = slice_file.readlines()

# Read pattern file
patterns = load_pattern_file()
for pattern in patterns:
    print pattern
    print
    # @TODO: do something to check if the slice_lines are vulnerable