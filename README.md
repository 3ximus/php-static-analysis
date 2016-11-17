# PHP static analysis tool

Parse PHP snippets to find possible vulnerabilities

## Usage:

`./analyzer <file.txt>`


## Description:

The parser reads a patterns file ([patterns.txt](https://github.com/3ximus/php-static-analysis/blob/master/patterns.txt)) that has the following information:

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
$test=mysql_real_escaped_string($vary);
$out=mysql_query($test,$var0);
```

This would generate the following trees:
```
               $var1           $var2      $var3      $varx
                 |                 \       /           |
                 |                  \     /            |
                 |                   \   /             |
                str1                 str2           END_NODE
                 |                     |
                 |                     |
                $vary                $varw
                /   \                  |
               /     \                 |
              /       \             END_NODE
         END_NODE   END_NODE
```

Variables are adde to the graph if they are assigned from an Entry Point ( defined in the pattern )

End Nodes are either a Sanitization funciton or a Sensitive sink ( defined in the pattern ), if a Sensitive sink exists in the tree the originating variables are marked as poisoned ( they will generate a vulnerability )

## [Known Issues](https://github.com/3ximus/php-static-analysis/issues)