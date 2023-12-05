<?php
session_start();
define("FINGERPRINT", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0");
define("DBUSER", "kaibro");
define("DBPASS", "superbig");
define("HOST", "localhost");
$flag = 'CGGC{fake_flag}';

function session_check() {
    if(!isset($_SESSION['login']) || $_SESSION['login'] == "") {
        header("Location: login.php");
        die("Plz login");
    }
}

function fingerprint_check() {
    if($_SERVER['HTTP_SSL_JA3'] !== FINGERPRINT) 
        die("Bad hacker! Wrong fingerprint!"); 
}

function generateRandomString($length = 10) {
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_1234567890';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[random_int(0, $charactersLength - 1)];
    }
    return $randomString;
}
