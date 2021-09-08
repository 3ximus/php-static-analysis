#ThisIsJustAComment attack with arg = ?argument=1;phpinfo();
$var = "value";
$v = $_GET['argument'];
eval("\$var = $v;");