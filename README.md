# crx3-utils

https://sigwait.org/~alex/blog/2019/04/01/crx3.html

Starting with Chrome 73, Chrome changed the package format for
extensions to the CRX3 file format.

    $ npm -g i crx3-utils

## Usage

Create a signed CRX3 file with a local private key:

    $ crx3-new private.pem < file.zip > extension.crx

Create a signed CRX3 file with AWS KMS (private key never leaves KMS):

    $ crx3-new --kms alias/my-signing-key < file.zip > extension.crx
    $ crx3-new --kms arn:aws:kms:us-east-1:123456789:key/abc-123 < file.zip > extension.crx

The util is intentionally bare bone: it doesn't generate a private key
for you (use openssl for that) & it doesn't compress your directory
(use zip for that).

## AWS KMS Signing

To use KMS signing, you need:

1. An RSA key in AWS KMS (minimum 2048-bit, recommend 4096-bit)
2. AWS credentials configured (via environment, IAM role, etc.)
3. IAM permissions for `kms:Sign` and `kms:GetPublicKey` on the key

This approach is more secure than storing keys in files or CI secrets:
- The private key material never leaves KMS
- Full audit logging of all signing operations
- No long-lived credentials if using OIDC federation

### Programmatic API

~~~javascript
const crx = require('crx3-utils')
const { KMSClient } = require('@aws-sdk/client-kms')

// With AWS KMS
const kmsClient = new KMSClient({ region: 'us-east-1' })
const kp = await crx.kmsKeypair(kmsClient, 'alias/my-signing-key')
const maker = new crx.Maker(kp, zipBuffer)
const crxBuffer = await maker.creat()

// With local key file (note: creat() is now async)
const kp = await crx.keypair('private.pem')
const maker = new crx.Maker(kp, zipBuffer)
const crxBuffer = await maker.creat()
~~~

Print info for a .crx downloaded from the Chome Web Store:

~~~
$ crx3-info < file.crx
id                   ckbpebiaofifhmkecjijobfafcfngfkj
header               1322
payload              8233
sha256_with_rsa      2 main_idx=1
sha256_with_ecdsa    1
~~~

(`main_idx` is the index of AsymmetricKeyProof that contains a public
key from which the id was derived during the .crx creation.)

Extract zip:

~~~
$ crx3-info < file.crx | awk '/^header/ {print $2}' \
    | xargs -I% dd if=file.crx iflag=skip_bytes skip=% > file.zip
~~~

Extract the 1st rsa public key:

~~~
$ crx3-info rsa 0 < file.crx
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj/u/XDdjlDyw7gHEtaaa
sZ9GdG8WOKAyJzXd8HFrDtz2Jcuy7er7MtWvHgNDA0bwpznbI5YdZeV4UfCEsA4S
rA5b3MnWTHwA1bgbiDM+L9rrqvcadcKuOlTeN48Q0ijmhHlNFbTzvT9W0zw/GKv8
LgXAHggxtmHQ/Z9PP2QNF5O8rUHHSL4AJ6hNcEKSBVSmbbjeVm4gSXDuED5r0nwx
vRtupDxGYp8IZpP5KlExqNu1nbkPc+igCTIB6XsqijagzxewUHCdovmkb2JNtskx
/PMIEv+TvWIx2BzqGp71gSh/dV7SJ3rClvWd2xj8dtxG8FfAWDTIIi0qZXWn2Qhi
zQIDAQAB
-----END PUBLIC KEY-----
~~~

Validate (returns 0 on success):

    $ crx3-verify rsa 0 public.pem < file.crx

## Breaking Changes (v0.0.4)

The `Maker` class methods are now async to support KMS:

- `maker.creat()` → `await maker.creat()`
- `maker.sign()` → `await maker.sign()`
- `maker.header()` → `await maker.header()`

## License

MIT.
