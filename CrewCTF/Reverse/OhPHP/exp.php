<?php
$encryption = "wCX3NcMho0BZO0SxG2kHxA==";
$ciphering = "AES-128-CBC";
$decryption_key_ord = "crew{php_1s_4";
$options = 2;
$str=array('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','_');
for ($x = 0; $x <= 36; $x++)
{
	for ($y = 0; $y <= 36; $y++)
	{
		for ($z = 0; $z <= 36; $z++)
		{
			srand(31337);
			$decryption_key = $decryption_key_ord.$str[$x].$str[$y].$str[$z];
			// echo $decryption_key;
			$decryption_iv = pack("L*",rand(),rand(),rand(),rand());
            $decryption=openssl_decrypt ($encryption, $ciphering, $decryption_key, $options, $decryption_iv);
		    echo $str[$x].$str[$y].$str[$z]. " is " . $decryption. "\n";
		}
	}
}
?>