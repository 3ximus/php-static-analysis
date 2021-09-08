if (condition) then
    $nis=$_POST['nis'];
else
    $nis=mysql_real_escape_string($_POST['nis']);
$query="SELECT *FROM siswa WHERE nis='$nis'";
$q=mysql_query($query,$koneksi);
