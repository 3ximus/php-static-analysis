# php-static-analysis
PHP static analysis tool

Parse PHP snippets to find possible vulnerabilities

The parser reads a patterns file ([patterns.txt](https://github.com/3ximus/php-static-analysis/blob/master/patterns.txt)) that has the following information:

```
Pattern: "SQL injection"
EntryPoints: ['$_GET', '$_POST', '$_COOKIE']
Sanitization functions: ['mysql_escape_string', 'mysql_real_escape_string', 'mysql_real_escape_string']
Sensitive sinks: ['mysql_query', 'mysql_unbuffered_query', 'mysql_db_query']
```

When parsing the following file:

```php
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
```

This would generate the following trees:
```
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
```

Variables are adde to the graph if they are assigned from an Entry Point ( defined in the pattern )

End Nodes are either a Sanitization funciton or a Sensitive sink ( defined in the pattern ), if a Sensitive sink exists in the tree the originating variables are marked as poisoned ( they will generate a vulnerability )
