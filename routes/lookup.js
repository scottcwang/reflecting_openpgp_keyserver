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
    return {
      data: [resp.data]
    };
  } catch (error) {
    throw new Error(error.errno || error.response.status);
  }
}

router.get('/', function (req, res, next) {
  let [username, service, ...hostname] = req.hostname.split('.');

  if (hostname.join('.') !== process.env.PKS_HOSTNAME) {
    throw new Error(
      'Specify both username and service: <username>.<service>.'
      + process.env.PKS_HOSTNAME
    );
  }

  // https://github.com/expressjs/express/issues/2259 Express.js 5 will
  // handle promise rejections
  (serviceReqEnum[service])(username).then(
    serviceRes => res.render('index', { title: serviceRes.data })
  ).catch(next);
});

module.exports = router;
