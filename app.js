var createError = require('http-errors');
var express = require('express');
var cors = require('cors');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var config = require('./config.json');


var oktaJWTConfig;
if (process.env.oktaJWTConfig) {
  // Change ' to "" for CI / CD scripts that can't pass " in an env var for the oktaJWTConfig
  var config = process.env.oktaJWTConfig.replace(/'/g, "\"");
  oktaJWTConfig = JSON.parse(config);
} else {
  oktaJWTConfig = config.okta;
}
console.log("oktaJWTConfig = " + oktaJWTConfig);
console.log("oktaJWTConfig = ") + JSON.stringify(oktaJWTConfig);
console.log("Found " + oktaJWTConfig.length + " verifiers");

const OktaJwtVerifier = require('@okta/jwt-verifier');
const verifiers = [];

for (x=0; x<oktaJWTConfig.length; x++) {
  console.log("Adding verifier. Issuer = " + oktaJWTConfig[x].issuer + ", ClientId = " + oktaJWTConfig[x].clientId);
  const oktaJwtVerifier = new OktaJwtVerifier({
    issuer: oktaJWTConfig[x].issuer, // required
    clientId: oktaJWTConfig[x].clientId
  });
  verifiers.push([oktaJwtVerifier, oktaJWTConfig[x].audience]);
}

var indexRouter = require('./routes/index');
var verifyRouter = require('./routes/verify');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');
app.set('env', 'development');

app.use(cors());
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/secure', verifyToken, verifyRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  console.log(JSON.stringify(err));
  res.render('error');
});

function verifyToken(req, res, next) {

  const bearerHeader = req.headers['authorization'];

  if (bearerHeader) {
    const bearer = bearerHeader.split(' ');
    const bearerToken = bearer[1];

    doTokenVerification(0, bearerToken, req, res, next);

  } else {
    // No bearer header provided
    // Return a 403 Forbidden error
    res.sendStatus(403);
  }
}

function doTokenVerification(x, bearerToken, req, res, next) {

  verifiers[x][0].verifyAccessToken(bearerToken, verifiers[x][1])
      .then(jwt => {
        req.sub = jwt.claims.sub;
        console.log("sub = " + req.sub);
        console.log("JWT verified");
        next();
      })
      .catch(err => {
        console.log("JWT failed verification for this verifier");
        console.log(err);
        if (x === verifiers.length-1) {
          console.log("JWT failed verification");
          // return a 403 Forbidden error
          res.sendStatus(403);
        } else {
          x = x + 1;
          doTokenVerification(x, bearerToken, req, res, next);
        }
      });
}

module.exports = app;
