var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var config = require('./config');

const OktaJwtVerifier = require('@okta/jwt-verifier');
 
const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: config.okta.issuer, // required
  clientId: config.okta.clientId
});

var indexRouter = require('./routes/index');
var verifyRouter = require('./routes/verify');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

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
  console.log(bearerHeader);
  
  if (bearerHeader) {
    const bearer = bearerHeader.split(' ');
    const bearerToken = bearer[1];
    oktaJwtVerifier.verifyAccessToken(bearerToken, 'api://default')
    .then(jwt => {
      req.sub = jwt.claims.sub;
      next();
    })
    .catch(err => {
      console.log(err);
      res.sendStatus(403);
    });
    
    
  } else {
    // Forbidden
    res.sendStatus(403);
  }
}

module.exports = app;
