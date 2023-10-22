<?php
//require "/flag.php"; 
if (isset($_POST['component'])) 
{
    $component = $_POST['component'];
    $lowercaseComponent = strtolower($component);
    $pattern_file = "/^cpu|gpu|hd|io|ram|psu$/";
    $keyword = "source";
    if (preg_match($pattern_file, $lowercaseComponent)) 
    {
        $lowercaseComponent = "./component/" . $lowercaseComponent;
        $file = fopen($lowercaseComponent, 'r');
        if ($file !== false)
        {
            while (($line = fgets($file)) !== false) 
            {
                echo "<br>";
                echo $line;
            }
        } 
        else
        {
            echo "No such file or directory1";
        }
        fclose($file);
    }
    elseif (strpos($lowercaseComponent, $keyword) !== false)
    {
        highlight_file(__FILE__);
    }
    else
    {
        echo "No such file or directory0";
    }   
}
    
?>