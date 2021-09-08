$var1=mysql_real_escape_string($_GET['idn']);
$query="SELECT *FROM siswa WHERE nis='$var1'";
$q=mysql_query($query,$koneksi);