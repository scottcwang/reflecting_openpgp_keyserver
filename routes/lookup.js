var express = require('express');
var router = express.Router();

var axios = require('axios');

serviceReqEnum = Object.freeze({
  'github': requestGitHub
})

async function requestGitHub(username) {
  try {
    let url = 'https://github.com/' + username + '.gpg'
    let resp = await axios.get(url);
    return resp;
  } catch (error) {
    return error;
  }
}

router.get('/', async function (req, res, next) {
  let [username, service, ...hostname] = req.hostname.split('.');

  if (hostname.join('.') !== process.env.PKS_HOSTNAME) {
    throw new Error(
      'Specify both username and service: <username>.<service>.'
      + process.env.PKS_HOSTNAME
    );
  }

  let serviceRes = await (serviceReqEnum[service])(username);

  res.render('index', { title: 'Express' });
});

module.exports = router;
