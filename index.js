var express = require('express');
var crypto = require('crypto');
var aes256 = require('aes256');
var app = express();
var { performance } = require('perf_hooks');
const bodyParser = require("body-parser")
/////////
const server = crypto.createECDH('secp256k1');

server.generateKeys();
let serverPublicKeyBase64 = server.getPublicKey().toString('base64');
/////////

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});
app.use(bodyParser.json());

app.get('/', function (req, res) {
  res.send({
    message: 'server'
  });
})

app.get('/key/:id', function (req, res) {
  const encrypted = aes256.encrypt(req.params.id, serverPublicKeyBase64);

  res.send({
    serverPublicKey: encrypted
  });
})


app.post('/:id', function (req, res) {
  var time = performance.now();

  const serverSharedKey = server.computeSecret(req.body.clientPublic, 'base64', 'hex')
  
  const decrypted = aes256.decrypt(serverSharedKey, req.body.encrypted);
  time = performance.now() - time;
  console.table({
    clientPublic: req.body.clientPublic,
    encrypted: req.body.encrypted
  })
  console.table({
    decrypted: JSON.parse(decrypted)
  })

  res.send({
    decryptedMessage: JSON.parse(decrypted),
    time
  });
});

app.post('/another/:id', function (req, res) {
  var time = performance.now();
  const decrypted = aes256.decrypt(req.params.id, req.body.body);
  console.table(JSON.parse(decrypted));
  time = performance.now() - time;


  res.send({
    decryptedMessage: JSON.parse(decrypted),
    time
  });
});

app.post('/simple/:id', function (req, res) {
  var time = performance.now();
  const body = req.body.body;
  time = performance.now() - time;
  console.table(body)

  res.send({
    decryptedMessage: body,
    time
  });
});

app.listen(4000, function () {
  console.log(' app listening on port 4000!');
});