<?php
include_once("config.php");
fingerprint_check();
session_check();
?>
<html style="box-shadow:inset 0 0 5rem rgba(0,0,0,.5)">
<head>
<title>Flag Slot Machine</title>
<meta charset="utf-8">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/css/bootstrap.min.css" integrity="sha384-PsH8R72JQ3SOdhVi3uxftmaW6Vc51MKb0q5P2rRUpPvrszuE4W1povHYgTpBfshb" crossorigin="anonymous">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
</head>

<body style="background-color:#333">
<br>
<div class="container">
<div class="jumbotron">
<h2 class="title is-2">Welcome!</h2>
<hr>
<div class="field">
	<p class="title is-4">Flag Slot Machine:</p>
	<p class="subtitle is-5"><a href='flag.php'>>> Link <<</a></p>
</div>
<div class="field">
	<p class="title is-4">Logout:</p>
	<p class="subtitle is-5"><a href='logout.php'>>> Link <<</a></p>
</div>
</div>
</div>
</body>
</html>
