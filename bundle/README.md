# AES Encryptor and Decryptor sample proxy bundle

This directory contains the configuration for a sample proxy bundle
that shows how to use the Java custom policy for doing AES Crypto.

## Using the Proxy

Import and deploy the Proxy to your favorite Edge organization + environment.

## Encrypt and Decrypt with a Passphrase

To encrypt data using a passphrase, invoke the proxy like so:

```
curl -i -H 'content-type: text/plain' -X POST \
 "https://$ORG-$ENV.apigee.net/aes-crypto/encrypt1?passphrase=Secret123" \
 -d 'The quick brown fox jumped over the lazy dog.'
```

This generates a key and IV from the passphrase, using a default number of iterations in PBKDF2. It uses the default salt, which is "Apigee-IloveAPIs". It then applies these values to the AES algorithm to encrypt the payload.


To decrypt data using a passphrase, invoke the proxy like so:

```
curl -i -H 'content-type: text/plain' -X POST \
 "https://$ORG-$ENV.apigee.net/aes-crypto/decrypt1?passphrase=Secret123&source_encoding=base64" \
 -d 'rZjFqahLBx/RdlqkNv8QpryerhWBnUaVOfi1MzTd6MSZFGLBGLF0+TGvppIcYTSL'
```

Again, the above generates the appropriate key and IV from the passphrase and salt, then uses those to decrypt.

## Encrypt and Decrypt with an Explicitly-provided Key and IV

To encrypt data using a key and IV that you provide, invoke the proxy like so:

```
curl -i -X POST https://$ORG-$ENV.apigee.net/aes-crypto/encrypt2 \
 -d 'key=2391652f01a99021d63789256e5d3d30' \
 -d 'iv=c5b4039aadf01a1da13d04570da45265' \
 -d 'cleartext=Whatever you want to encrypt goes here.'
```

The policy decodes the key and IV as base16 (hex). You can use any hex-encoded
octet stream of 16 bytes that you like.

To decrypt:

```
curl -i -X POST https://$ORG-$ENV.apigee.net/aes-crypto/decrypt2 \
 -d 'key=2391652f01a99021d63789256e5d3d30' \
 -d 'iv=c5b4039aadf01a1da13d04570da45265' \
 -d 'source_decoding=base64url' \
 -d 'ciphertext=cjJTqwvqlKDnX-gOSGLbVNMMKhJkD6MxfSYu7warI49Xdk17mF0ps8qfp12Xj49konM1YL5K9JC2pD3LiCHkbOpvMmnN1Rm1dgzLbSeysAPtV4FRqlX6SvTv1-7ToMeBhTVf7u5XW607umfVauUCvwqar9C7mLB4ivqW0p4RJjW5XDQzmHPI7JtO0rILsJlnXficbHsv3sh1ShR6YshgKg'
```

## Encrypt with a generated key and IV, and then Decrypt with same

To encrypt data using a generated key and IV, invoke the proxy like so:

```
curl -i -X POST https://$ORG-$ENV.apigee.net/aes-crypto/encrypt4 \
 -d 'cleartext=Whatever you want to encrypt goes here.'
```

This API will emit the ciphertext along with the generated key and IV.

To decrypt:

```
curl -i -X POST https://$ORG-$ENV.apigee.net/aes-crypto/decrypt2 \
 -d 'key=KEY_FROM_OUTPUT' \
 -d 'iv=IV_FROM_OUTPUT' \
 -d 'source_decoding=base64url' \
 -d 'ciphertext=CIPHERTEXT_FROM_OUTPUT'
```

## Bugs

None?
