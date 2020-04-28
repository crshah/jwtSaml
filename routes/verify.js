var express = require('express');
var router = express.Router();
var client = require('redis').createClient();
var saml = require('../saml');
var logger = require('morgan');
var config = require('../config');

router.post('/authRedirect', async function(req, res, next) {
  const user = { email: req.sub };
  //console.log(JSON.stringify(sp));
  const { id, context } = await saml.idp.createLoginResponse(saml.sp, null, 'post', user, saml.createTemplateCallback(saml.idp, saml.sp, user));
  //console.log(JSON.stringify(context));
  var val = {};
  val.relayState = req.body.redirectUrl;
  val.samlResponse = context;
  client.set(id, JSON.stringify(val), 'EX', 60*5); 
  var hostname = config.hostname || req.headers.host;
  res.json({ authnUrl: `https://${hostname}/verifyandredirect/${id}`});
});

module.exports = router;
