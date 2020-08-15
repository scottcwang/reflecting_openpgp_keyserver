var util = require('util')

var express = require('express');
var router = express.Router();

var axios = require('axios');

var openpgp = require('openpgp');
const { map } = require('../app');

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

async function parseUsers(key) {
  return Promise.all(
    key.getUserIds().map(
      async userId => {
        let { selfCertification } = await key.getPrimaryUser(
          undefined, userId
        );
        return {
          userId: userId,
          isRevoked: selfCertification.revoked,
          expirationTime: selfCertification.getExpirationTime(),
          creationTime: selfCertification.created
        }
      }
    )
  );
}

async function parseArmoredKey(keyString) {
  readResult = await openpgp.key.readArmored(keyString);

  return await Promise.all(
    readResult.keys.map(
      async key => ({
        users: parseUsers(key),
        keyId: key.getKeyId(),
        algorithm: key.getAlgorithmInfo(),
        isRevoked: await key.isRevoked(),
        expirationTime: await key.getExpirationTime(),
        creationTime: key.getCreationTime()
      })
    )
  );
}

router.get('/', function (req, res, next) {
  let username;
  let service;
  let hostname;

  if (req.query.hasOwnProperty('username')) {
    username = req.query.username;
    if (req.query.hasOwnProperty('service')) {
      service = req.query.service;
      hostname = [req.hostname];
    } else {
      [service, ...hostname] = req.hostname.split('.')
    }
  } else if (req.query.hasOwnProperty('service')) {
    service = req.query.service;
    [username, ...hostname] = req.hostname.split('.')
  } else {
    [username, service, ...hostname] = req.hostname.split('.');
  }

  if (hostname.join('.') !== process.env.PKS_HOSTNAME) {
    throw new Error(
      'Specify both username and service: <username>.<service>.'
      + process.env.PKS_HOSTNAME
    );
  }

  // https://github.com/expressjs/express/issues/2259 Express.js 5 will
  // handle promise rejections
  (serviceReqEnum[service])(username).then(
    async serviceRes => (
      await Promise.all(
        serviceRes.data.map(parseArmoredKey)
      )
    ).flat()
  ).then(
    readResults => res.render(
      'index',
      {
        title: util.inspect(
          readResults,
          { depth: 4 }
        )
      }
    )
  ).catch(next);

});

module.exports = router;
