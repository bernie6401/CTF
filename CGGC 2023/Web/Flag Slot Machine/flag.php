<?php
include_once("config.php");

if(isset($_GET["secret"])) {
    $pwd = $_GET["secret"];
    $dbname = 'secret_db';
    $conn = new mysqli(HOST, DBUSER, DBPASS, $dbname);
    
    if ($conn->connect_error) {
        die('Connection failed: ' . $conn->connect_error);
    }

    $conn->set_charset("utf8");

    $stmt = $conn->prepare("SELECT * FROM s3cret_table");
    $stmt->execute();

    $result = $stmt->get_result();

    $response = array("data" => generateRandomString(strlen($flag)));
    if ($result->num_rows > 0) {
        $res = $result->fetch_assoc();
        if($res["secret"] == $pwd)
            $response = array("data" => $flag);
    }

    header('Content-Type: application/json');
    die(json_encode($response));
}
?>
<html>
<head>
    <title>Flag Slot Machine</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
    <style>
    canvas{
      position: absolute;
      background: #111;
      height: 80%;
      width: 100%;
      left: 0;
      top: 0;
    }

    body {
        margin: 0;
        padding: 0;
        position: relative;
        background-color: #111;
    }

    .bottom-div {
        position: absolute;
        bottom: 5%;
        left: 0;
        width: 100%;
        background-color: #111;
        color: white;
        text-align: center;
        padding: 10px;
    }
    </style>
</head>
<body>
<canvas></canvas>
<div class="bottom-div">
    <div class="field">
        <input type="text" class="input is-primary" name="secret" placeholder="input correct secret to get the flag...">
    </div>
    <div class="field">
        <button class="button is-primary is-large" onclick=startAni()>SPIN!</button>
    </div>
</div>

<script>
text = '<?php echo generateRandomString(strlen($flag)); ?>';  // The message displayed
chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_1234567890';  // All possible Charactrers
scale = 50;  // Font size and overall scale
breaks = 0.003;  // Speed loss per frame
endSpeed = 0.1;  // Speed at which the letter stops
firstLetter = 220;  // Number of frames untill the first letter stopps (60 frames per second)
delay = 40;  // Number of frames between letters stopping

canvas = document.querySelector('canvas');
ctx = canvas.getContext('2d');

text = text.split('');
chars = chars.split('');
charMap = [];
offset = [];
offsetV = [];

for(var i = 0; i < chars.length; i++)
  charMap[chars[i]] = i;

for(var i = 0; i < text.length; i++){
  var f = firstLetter + delay * i;
  offsetV[i] = endSpeed + breaks * f;
  offset[i] = -(1 + f) * (breaks * f + 2 * endSpeed) / 2;
}

(onresize = function(){
  canvas.width = canvas.clientWidth;
  canvas.height = canvas.clientHeight;
})();

requestAnimationFrame(loop = function(){
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.globalAlpha = 1;
      ctx.fillStyle = '#622';
      ctx.fillRect(0, (canvas.height-scale) / 2, canvas.width, scale);
      for(var i = 0; i < text.length; i++){
	ctx.fillStyle = '#ccc';
	ctx.textBaseline = 'middle';
	ctx.textAlign = 'center';
	ctx.setTransform(1, 0, 0, 1, Math.floor((canvas.width - scale * (text.length - 1)) / 2), Math.floor(canvas.height / 2));
	var o = offset[i];
	while(o < 0) o++;
	o %= 1;
	var h = Math.ceil(canvas.height / 2 / scale)
	for(var j = -h; j < h; j++){
	  var c = charMap[text[i]] + j - Math.floor(offset[i]);
	  while(c < 0) c += chars.length;
	  c %= chars.length;
	  var s = 1 - Math.abs(j + o) / (canvas.height / 2 / scale + 1)
	  ctx.globalAlpha = s
	  ctx.font = scale * s + 'px Helvetica'
	  ctx.fillText(chars[c], scale * i, (j + o) * scale);
	}
	offset[i] += offsetV[i];
	offsetV[i] -= breaks;
	if(offsetV[i] < endSpeed){
	  offset[i] = 0;
	  offsetV[i] = 0;
	}
      }
});


function fetchFlag() {
    var sec = document.getElementsByName("secret")[0].value;
    fetch('flag.php?secret=' + sec)
    .then(response => {
        if (!response.ok)
            throw new Error('Error!');
        return response.json();
    })
    .then(data => {
        text = data['data'];
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function startAni() {
	charMap = [];
	offset = [];
	offsetV = [];
	for(var i = 0; i < chars.length; i++){
	  charMap[chars[i]] = i;
	}

	for(var i = 0; i < text.length; i++){
	  var f = firstLetter + delay * i;
	  offsetV[i] = endSpeed + breaks * f;
	  offset[i] = -(1 + f) * (breaks * f + 2 * endSpeed) / 2;
	}

    fetchFlag();
    requestAnimationFrame(loop = function(){
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.globalAlpha = 1;
      ctx.fillStyle = '#622';
      ctx.fillRect(0, (canvas.height - scale) / 2, canvas.width, scale);
      for(var i = 0; i < text.length; i++){
        ctx.fillStyle = '#ccc';
        ctx.textBaseline = 'middle';
        ctx.textAlign = 'center';
        ctx.setTransform(1, 0, 0, 1, Math.floor((canvas.width - scale * (text.length - 1)) / 2), Math.floor(canvas.height / 2));
        var o = offset[i];
        while(o < 0) o++;
        o %= 1;
        var h = Math.ceil(canvas.height / 2 / scale)
        for(var j = -h; j < h; j++){
          var c = charMap[text[i]] + j - Math.floor(offset[i]);
          while(c < 0) c += chars.length;
          c %= chars.length;
          var s = 1 - Math.abs(j + o) / (canvas.height / 2 / scale + 1)
          ctx.globalAlpha = s
          ctx.font = scale*s + 'px Helvetica'
          ctx.fillText(chars[c], scale * i, (j + o) * scale);
        }
        offset[i] += offsetV[i];
        offsetV[i] -= breaks;
        if(offsetV[i] < endSpeed){
          offset[i] = 0;
          offsetV[i] = 0;
        }
      }

      requestAnimationFrame(loop);
    });
}
</script>
</body>
</html>
