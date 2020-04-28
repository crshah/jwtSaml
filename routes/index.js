var express = require('express');
var router = express.Router();
var client = require('redis').createClient();
var saml = require('../saml');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});



router.get('/verifyandredirect/:samlid', function (req, res) {
  var samlid = req.params.samlid;
  console.log(samlid);
  client.get(samlid, function (err, valstr) {
    var val = JSON.parse(valstr);
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
