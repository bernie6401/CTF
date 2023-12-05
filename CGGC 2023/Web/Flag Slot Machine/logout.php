<?php
include_once("config.php");
fingerprint_check();
session_destroy();
header("Location: login.php");