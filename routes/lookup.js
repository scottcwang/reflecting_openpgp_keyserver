var express = require('express');
var router = express.Router();

router.get('/', function (req, res, next) {
  let [username, service, ...hostname] = req.hostname.split('.');

  if (hostname.join('.') !== process.env.PKS_HOSTNAME) {
    throw new Error(
      'Specify both username and service: <username>.<service>.'
      + process.env.PKS_HOSTNAME
    );
  }

  res.render('index', { title: 'Express' });
});

module.exports = router;
