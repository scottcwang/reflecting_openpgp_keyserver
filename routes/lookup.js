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

function parseUsers(key) {
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
        key: key,
        users: await parseUsers(key),
        fingerprints: key.getKeys().map(
          key => key.getFingerprint().toLowerCase()
        ),
        algorithm: key.getAlgorithmInfo(),
        isRevoked: await key.isRevoked(),
        expirationTime: await key.getExpirationTime(),
        creationTime: key.getCreationTime()
      })
    )
  );
}

router.get('/', async function (req, res, next) {
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
    next(new Error(
      'Specify both username and service: <username>.<service>.'
      + process.env.PKS_HOSTNAME
    ));
    return;
  }

  if (!['index', 'get'].includes(req.query.op)) {
    next(new Error(
      'Unrecognized op; must be index or get'
    ));
    return;
  }

  if (!req.query.search) {
    next(new Error(
      'Specify search query param'
    ));
    return;
  }

  let search = req.query.search.toLowerCase();

  let searchHex;
  if (parseInt(search, 16)) {
    let s = search.startsWith('0x') ? search.slice(2) : search;
    if (s.length === 40 || s.length === 16) {
      searchHex = s;
    }
  }

  // https://github.com/expressjs/express/issues/2259 Express.js 5 will
  // handle promise rejections

  let keys;
  try {
    let serviceRes = await ((serviceReqEnum[service])(username));
    keys = await Promise.all(serviceRes.data.map(parseArmoredKey));
  } catch (error) {
    next(error);
    return;
  }

  let filteredKeys = keys.flat().filter(
    key => (
      key.fingerprints.some(fingerprint => fingerprint.endsWith(searchHex))
      || key.users.some(user => user.userId.includes(search))
    )
  );

  res.render(
    'index',
    {
      title: util.inspect(
        filteredKeys,
        { depth: 4 }
      )
    }
  );

});

module.exports = router;
