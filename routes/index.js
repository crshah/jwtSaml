var express = require('express');
var router = express.Router();
var path = require('path');
var config = require('../config.json');

var redisPort = process.env.redisPort || config.redis.port;
var redisHost = process.env.redisHost || config.redis.host;
var redisPassword = process.env.redisPassword || config.redis.password;

var client = require('redis').createClient(config.redis);
//var client = require('redis').createClient(redisPort, redisHost,
//    {auth_pass: redisPassword, tls: {servername: redisHost}});

var saml = require('../saml.js');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.get('/verifyandredirect/:samlid', function (req, res) {

  var samlid = req.params.samlid;
  client.get(samlid, function (err, valstr) {
    var val = JSON.parse(valstr);
    //TODO - Add config option to redirect to custom error template.
    if(!val) {
        val = {samlResponse: "",
                relayState: ""}
    }
    var html = `
          <html>
            <body Onload="document.forms[0].submit()">
              <form method="POST" action="${saml.sp.entityMeta.getAssertionConsumerService('post')}">
                <input type="hidden" name="SAMLResponse" value="${val.samlResponse}">
                <input type="hidden" name="RelayState" value="${val.relayState}">            
              </form>
            </body>
          </html>
        `
    res.send(html);
  });
  
});

module.exports = router;
