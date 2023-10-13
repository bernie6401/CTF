const express = require("express");
const ethers = require("ethers");
const path = require("path");

const app = express();

app.use(express.urlencoded());
app.use(express.json());

app.get("/", function(_req, res) {
  res.sendFile(path.join(__dirname + "/server.js"));
});

function isValidData(data) {
  if (/^0x[0-9a-fA-F]+$/.test(data)) {
    return true;
  }
  return false;
}

app.post("/exploit", async function(req, res) {
  try {
    const message = req.body.message;
    const signature = req.body.signature;
    if (!isValidData(signature) || isValidData(message)) {
      res.send("wrong data");
      return;
    }

    const signerAddr = ethers.utils.verifyMessage(message, signature);
    console.log(signerAddr);
    console.log(ethers.utils.getAddress(message));
    if (signerAddr === ethers.utils.getAddress(message)) {
      const FLAG = process.env.FLAG || "get flag but something wrong, please contact admin";
      res.send(FLAG);
      return;
    }
  } catch (e) {
    console.error(e);
    res.send("error");
    return;
  }

  res.send("wrong");
  return;
});

const port = process.env.PORT || 3000;
app.listen(port);
console.log(`Server listening on port ${port}`);
