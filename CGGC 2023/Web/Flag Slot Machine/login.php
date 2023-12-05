<?php
include_once("config.php");
fingerprint_check();

if(isset($_POST['user']) && isset($_POST['pwd'])) {
    $user = $_POST['user'];
    $pwd = $_POST['pwd'];
} else {
    $user = $pwd = "";
}
?>
<html style="box-shadow:inset 0 0 5rem rgba(0,0,0,.5)">
<head>
<title>Flag Slot Machine</title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/css/bootstrap.min.css" integrity="sha384-PsH8R72JQ3SOdhVi3uxftmaW6Vc51MKb0q5P2rRUpPvrszuE4W1povHYgTpBfshb" crossorigin="anonymous">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
<meta charset="utf-8">
</head>

<body style="background-color:#333">
<br>
<div class="container">
<div class="jumbotron">
<?php
if($user != "" && $pwd != "") {
	$dbname = 'slot_db';
	$conn = new mysqli(HOST, DBUSER, DBPASS, $dbname);
	if ($conn->connect_error) {
	    die('Connection failed: ' . $conn->connect_error);
	}

	$conn->set_charset("utf8");
	$stmt = $conn->prepare("SELECT * FROM users WHERE username = '" . $user . "' and password = '" . md5($pwd) . "'");
	$stmt->execute();
	$result = $stmt->get_result();

	if ($result->num_rows > 0) {
	    $res = $result->fetch_assoc();
	    $_SESSION['login'] = $res["username"];
	    echo "<div>Login successful!</div>";
	    echo "<script>setTimeout(function(){ window.location.href = 'index.php'; }, 1000);</script>";
	} else {
	    echo "<div class=\"alert alert-danger\" role=\"alert\">Login failed! QAQ</div>";
	}
} else {
	echo <<<EOF
	<h2 class="title is-2">Login - Flag Slot Machine</h2>
	<br>
	<form method="post">
	<div class="field">
		<input type="text" class="input" name="user" placeholder="Username...">
	</div>
	<div class="field">
		<input type="password" class="input" name="pwd" placeholder="Password...">
	</div>
	<input type="submit" class="button is-primary"><br>
	</form>
EOF;

}
?>
<br/>
<br/>
</div>
</div>
</body>
</html>
