# PHP static analysis tool

Parse PHP snippets to find possible vulnerabilities

## Usage:

```
analyzer.py [-h] [-p PATTERN_FILE] [-n PATTERN_NUMBER] [-v [VERBOSE]] [-l]
                   file [file ...]
```


## Description:

The parser reads a patterns file provider or the default ([patterns.txt](https://github.com/3ximus/php-static-analysis/blob/master/patterns.txt)), if available, that has the following information in the following format:

```
Pattern: "SQL injection"
EntryPoints: ['$_GET', '$_POST', '$_COOKIE']
Sanitization functions: ['mysql_escape_string', 'mysql_real_escape_string', 'mysql_real_escape_string']
Sensitive sinks: ['mysql_query', 'mysql_unbuffered_query', 'mysql_db_query']
```

When parsing the following file:

```php
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

```

This would generate the following trees:
```
               $var1           $var2      $var3      $varx       $varx
                 |                 \       /           |           |
                 |                  \     /            |           |
                 |                   \   /             |           |
                str1                 str2           END_NODE    END_NODE
                 |                     |
                 |                     |
                $vary                $varw
                /   \                  |
               /     \                 |
              /       \             END_NODE
         END_NODE   END_NODE
```

In the program output the tree would be as follows:

```php
├── [ end7 ] - mysql_query
│     └── [ $vary ]
│           └── [ str5 ] - "SELECT var1,nis,sem...
│                 └── [ $var1 ]
│                       └── [ $_GET ]
├── [ end8 ] - mysql_query
│     └── [ $varw ]
│           └── [ str6 ] - "SELECT var1,nis,sem...
│                 ├── [ $var2 ]
│                 │     └── [ $_POST ]
│                 └── [ $var3 ]
│                       └── [ $_COOKIE ]
├── [ end9 ] - mysql_query
│     └── [ $varx ]
│           └── [ $_POST ]
└── [ end10 ] - mysql_real_escape_string
      └── [ $varx ]
            └── [ $_POST ]

 ----- > examples/readme_example.txt is vulnerable to: SQL injection - MySQL < -----

$var1=$_GET['idn'] <- Entry Point ($var1)
$var2=$_POST['sis'] <- Entry Point ($var2)
$var3=$_COOKIE['ll'] <- Entry Point ($var3)
$varx=$_POST['ss'] <- Entry Point ($varx) <- Entry Point ($varx)
$vary="SELECT var1,nis,semester FROM nilai WHERE nis='$var1'GROUP BY semester"
$varw="SELECT var1,nis,semester FROM nilai WHERE nis='$var2' AND ll='$var3' GROUP BY semester"
$varz=mysql_query($vary,$var0) <- Sensitive Sink (end7)
$v1=mysql_query($varw,$var0) <- Sensitive Sink (end8)
$v2=mysql_query($varx,$var0) <- Sensitive Sink (end9)
$test=mysql_real_escape_string($varx) <- Sanitization Function (end10)
$out=mysql_query($test,$var0)

```

*Generated with `./analyzer.py examples/readme_example.txt -v`*



Variables are adde to the graph if they are assigned from an Entry Point ( defined in the pattern )

End Nodes are either a Sanitization funciton or a Sensitive sink ( defined in the pattern ), if a Sensitive sink exists in the tree the originating variables are marked as poisoned ( they will generate a vulnerability )

## [Known Issues](https://github.com/3ximus/php-static-analysis/issues?q=is%3Aissue+is%3Aopen+label%3Abug)