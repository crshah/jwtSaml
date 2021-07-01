var express = require('express');
var router = express.Router();
var path = require('path');
var config = require('../config.json');

var redisPort = process.env.redisPort || config.redis.port || 6379;
var redisHost = process.env.redisHost || config.redis.host;
var redisPassword = process.env.redisPassword || config.redis.password;
var ttl = process.env.redisTTL || config.redis.ttl;

var client = require('redis').createClient();

//var client = require('redis').createClient(redisPort, redisHost,
//    {auth_pass: redisPassword, tls: {servername: redisHost}});

var saml = require('../saml.js');
var logger = require('morgan');

router.post('/authRedirect', async function(req, res, next) {

  const user = { email: req.sub };
  const { id, context } = await saml.idp.createLoginResponse(saml.sp, null, 'post', user, saml.createTemplateCallback(saml.idp, saml.sp, user));
  var val = {};
  val.relayState = req.body.redirectUrl;
  val.samlResponse = context;
  console.log(context);
  client.set(id, JSON.stringify(val), 'EX', ttl || 60*5); 
  var hostname = process.env.hostname || req.headers.host;

  res.json({ authnUrl: `https://${hostname}/verifyandredirect/${id}`});
});

module.exports = router;

