var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var lookupRouter = require('./routes/lookup');

require('dotenv').config();

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/pks/lookup', lookupRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(
    501,
    'This server implements the route /pks/lookup as per the OpenPGP HTTP '
    + 'Keyserver Protocol. To look up <username>\'s GPG keys at <service>, '
    + 'specify https://<username>-<service>.'
    + process.env.PKS_HOSTNAME
    + ' as the keyserver in an OpenPGP-compatible client.'
  ));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
