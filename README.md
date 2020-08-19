# reflecting-openpgp-keyserver

This is an API, served from ExpressJS on Node.js, that reflects users'
OpenPGP keys from version control system hosting services.

Currently, [user keys on GitHub](https://docs.github.com/en/github/authenticating-to-github/managing-commit-signature-verification)
are supported. To load &lt;username>'s keys on GitHub, specify

```
https://<username>-github.reflecting-openpgp-keyserver.duckdns.org
```

as the keyserver address in your OpenPGP-compatible client. For example, here
are my keys:

```
$ gpg --keyserver https://scottcwang-github.reflecting-openpgp-keyserver.duckdns.org --search-keys wang
gpg: data source: https://scottcwang-github.reflecting-openpgp-keyserver.duckdns.org:443
(1)     Scott C Wang <wangsc@cs.wisc.edu>
          4096 bit RSA key 8D368D366BEA0168, created: 2020-08-13, expires: 2020-08-20
(2)     Scott C Wang <scottcwang@users.noreply.github.com>
          256 bit EDDSA key 329716271E38BFB9, created: 2020-08-13
Keys 1-2 of 2 for "wang".  Enter number(s), N)ext, or Q)uit > 1
gpg: key 8D368D366BEA0168: public key "wangsc@cs.wisc.edu>" imported
gpg: no ultimately trusted keys found
gpg: Total number processed: 1
gpg:               imported: 1
```

## Why?

In a version control system, OpenPGP keys facilitate:

* Encrypted communication about security issues
* Validation of commit signatures
* Validation of package signatures on downloaded releases
* Verification of maintaners' email addresses and other contact details

Managing OpenPGP keys through separate keyservers causes issues:

* Using a separate keyserver presents a maintenance burden, which foments the
  insecure practice of using long-lived keys
* Many keyservers don't verify the User ID packets in the keys they host, so
  can't be trusted
* Many keyservers allow the world to add signature packets to a key, which
  invites key poisoning abuse
* A fingerprint posted in a project's security policy document isn't readily
  machine-readable

Consequently, a better solution is to manage OpenPGP keys using the version
control system. However, it's tedious to have to `curl` keys from a
version control system hosting service, then import them manually into an
OpenPGP client.

`reflecting-openpgp-keyserver` makes it easy to find and use the publicly
available, verified keys of a known user on a version control system
hosting service.

## Specification

This API exposes the `GET /pks/lookup` endpoint specified by the
[HTTP Keyserver Protocol](https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00):

* The `op` query variable may be either `get` or `index`
* The `search` variable may be one of:
  * a hexadecimal key ID (16 bytes), optionally preceded by `0x`
  * a fingerprint (40 bytes), optionally preceded by `0x`
  * a string (returns keys where the user ID string contains this string)
  * `*` (returns all keys)
* The `option` variable is always assumed to be `mr` (machine-readable output)
* The `fingerprint` variable is always assumed to be `on`
* The `exact` variable is always ignored

Commits created through the GitHub web interface are signed by the
key of the hardcoded `web-flow` user, which is accessible as the key with
fingerprint `4AEE18F83AFDEB23` at
`web-flow-github.reflecting-openpgp-keyserver.duckdns.org`.

