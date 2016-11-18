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