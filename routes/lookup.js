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
    if (error.response) {
      if (error.response.status === 404) {
        throw {
          status: 404,
          message: 'GitHub has no username ' + username
        };
      } else {
        throw {
          status: 502,
          message: 'GitHub error: ' + error.toString()
        };
      }
    }
    throw {
      status: 500,
      message: 'Internal error: ' + error.toString()
    };
  }
}

function parseUsers(key) {
  return Promise.all(
    key.getUserIds().map(
      async userId => {
        try {
          let { selfCertification } = await key.getPrimaryUser(
            undefined, userId
          );
          return {
            userId: userId,
            isRevoked: selfCertification.revoked,
            expirationTime: selfCertification.getExpirationTime(),
            creationTime: selfCertification.created
          };
        } catch (error) {
          return {
            userId: userId,
            isRevoked: false,
            expirationTime: Infinity,
            creationTime: NaN
          };
        }
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
        isRevoked: await key.isRevoked().catch(error => false),
        expirationTime: await key.getExpirationTime().catch(error => Infinity),
        creationTime: key.getCreationTime()
      })
    )
  );
}

function getCreationTime(obj) {
  return !isNaN(obj.creationTime)
    ? Math.floor(obj.creationTime.getTime() / 1000)
    : "";
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

router.get('/', function (req, res, next) {
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
    let username_service;
    [username_service, ...hostname] = req.hostname.split('.');
    let usernameServiceSplit = username_service.split('-');
    username = usernameServiceSplit.slice(0, -1).join('-');
    service = usernameServiceSplit[usernameServiceSplit.length - 1];
  }

  if (hostname.join('.') !== process.env.PKS_HOSTNAME) {
    throw {
      status: 400,
      message: 'Specify both username and service: <username>-<service>.'
        + process.env.PKS_HOSTNAME
    };
  }

  let op = req.query.op;
  if (!['index', 'get'].includes(op)) {
    throw {
      status: 501,
      message: 'Unrecognized op; must be index or get'
    };
  }

  if (!req.query.search) {
    throw {
      status: 400,
      message: 'Specify search query param'
    };
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

  if (!(service in serviceReqEnum)) {
    throw {
      status: 501,
      message: 'Service ' + service + ' not implemented'
    };
  }

  ((serviceReqEnum[service])(username)).then(
    serviceRes => Promise.all(serviceRes.data.map(parseArmoredKey))
  ).then(
    keys => {
      let filteredKeys = keys.flat().filter(
        key => (
          key.fingerprints.some(fingerprint => fingerprint.endsWith(searchHex))
          || key.users.some(user => user.userId.toLowerCase().includes(search))
        )
      );

      if (filteredKeys.length === 0) {
        throw {
          status: 404,
          message: 'No keys found for ' + req.query.search
        };
      }

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

        res.set('Content-Type', 'application/pgp-keys');
        res.write(armoredKey);
        res.send();
        return;
      } else {
        throw {
          status: 501,
          message: 'Unrecognized op; must be index or get'
        };
      }
    }
  ).catch(next);

});

module.exports = router;
