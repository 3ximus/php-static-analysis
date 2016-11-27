$nis=mysql_real_escape_string($_POST['nis']);
$query="SELECT *FROM siswa WHERE nis='$nis'";
$q=mysql_query($query,$koneksi);
