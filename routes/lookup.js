var util = require('util');

var express = require('express');
var router = express.Router();

var axios = require('axios');

var openpgp = require('openpgp');

const serviceReqEnum = Object.freeze({
  'github': requestGitHub
});

async function requestGitHub(username) {
  try {
    let url = 'https://github.com/' + username + '.gpg';
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
        };
      }
    )
  );
}

async function parseArmoredKey(keyString) {
  let readResult = await openpgp.key.readArmored(keyString);

  return await Promise.all(
    readResult.keys.map(
      async key => ({
        key: key,
        users: await parseUsers(key),
        fingerprints: key.getKeys().map(
          key => key.getFingerprint().toLowerCase()
        ),
        algorithm: openpgp.enums.write(
          openpgp.enums.publicKey, key.getAlgorithmInfo().algorithm
        ),
        bits: (
          key.getAlgorithmInfo().rsaBits
            ? key.getAlgorithmInfo().rsaBits
            : (
              new openpgp.crypto.publicKey.elliptic.Curve(
                key.getAlgorithmInfo().curve
              )
            ).payloadSize * 8
        ),
        isRevoked: await key.isRevoked(),
        expirationTime: await key.getExpirationTime(),
        creationTime: key.getCreationTime()
      })
    )
  );
}

function getCreationTime(obj) {
  return Math.floor(obj.creationTime.getTime() / 1000);
}

function getExpirationTime(obj) {
  return obj.expirationTime !== Infinity
    ? Math.floor(obj.expirationTime.getTime() / 1000)
    : "";
}

function getFlags(obj) {
  return (obj.isRevoked ? "r" : "")
    + (
      obj.expirationTime !== Infinity && obj.expirationTime < new Date()
        ? "e"
        : ""
    );
}

function mrIndexUser(users) {
  return users.map(
    user => [
      "uid",
      encodeURI(user.userId),
      getCreationTime(user),
      getExpirationTime(user),
      getFlags(user)
    ].join(":") + "\n"
  ).join("");
}

function mrIndexKey(keys) {
  return keys.map(
    key => [
      "pub",
      key.fingerprints[0].toUpperCase(),
      key.algorithm,
      key.bits,
      getCreationTime(key),
      getExpirationTime(key),
      getFlags(key)
    ].join(":") + "\n"
      + mrIndexUser(key.users)
  ).join("");
}

router.get('/', async function (req, res, next) {
  let username;
  let service;
  let hostname;

  if ('username' in req.query) {
    username = req.query.username;
    if ('service' in req.query) {
      service = req.query.service;
      hostname = [req.hostname];
    } else {
      [service, ...hostname] = req.hostname.split('.');
    }
  } else if ('service' in req.query) {
    service = req.query.service;
    [username, ...hostname] = req.hostname.split('.');
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

  let op = req.query.op;
  if (!['index', 'get'].includes(op)) {
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

  if (search === "*") {
    search = "";
  }

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
      || key.users.some(user => user.userId.toLowerCase().includes(search))
    )
  );

  if (op === 'index') {
    res.set('Content-Type', 'text/plain');
    res.write('info:1:' + filteredKeys.length + '\n');
    res.write(mrIndexKey(filteredKeys));
    res.send();
    return;
  }
  else if (op === 'get') {
    let combinedPacketList = new openpgp.packet.List();
    filteredKeys.forEach(
      key => combinedPacketList.concat(key.key.toPacketlist())
    );
    let combinedKey = new openpgp.key.Key(combinedPacketList);
    let armoredKey = combinedKey.armor();

    res.render(
      'index',
      {
        title: util.inspect(
          armoredKey,
          { depth: 10 }
        )
      }
    );
  } else {
    next(new Error(
      'Unrecognized op; must be index or get'
    ));
  }

});

module.exports = router;
