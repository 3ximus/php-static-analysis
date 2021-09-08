$someVar=$_POST['cat'];
$cat=$_POST['cat'];
$idx=$_GET['id'];
$test=$_COOKIE['id'];

$idvv = $idx;

$other="UPDATE cat SET '$test'";

$id=$_POST['id'];

$blabla = "MY SUPER QUERY '$someVar'";
$an="UPDATE cat SET '$blabla' AND '$idvv'";
$edit="UPDATE cat SET cat='$cat' WHERE id_cat='$id' AND to_screw_this_up_use_SomeVar_here='$someVa'";

$kitty=$_COOKIE['id'];

$crl=mysql_query($edit,$an, $other);

$hum=mysql_real_escape_string($kitty);

$ffff = "MY SUPER QUERY '$kitty'";

$zzz=mysql_query($hum);

$xxx=mysql_query($ffff,$hum, $id);