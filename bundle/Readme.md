# AES Encryptor and Decryptor sample proxy bundle

This directory contains the configuration for a sample proxy bundle
that shows how to use the Java custom policy for doing AES Crypto.

## Using the Proxy

Import and deploy the Proxy to your favorite Edge organization + environment.

To encrypt data using a passphrase, invoke the proxy like so:

```
curl -i -H 'content-type: text/plain' -X POST \
 'https://ORGNAME-ENVNAME.apigee.net/aes-trial/encrypt?passphrase=Secret123' \
 -d 'The quick brown fox jumped over the lazy dog.'
```

To decrypt data using a passphrase, invoke the proxy like so:

```
curl -i -H 'content-type: text/plain' -X POST \
 'https://ORGNAME-ENVNAME.apigee.net/aes-trial/decrypt1?passphrase=Secret123&source_encoding=base64' \
 -d 'rZjFqahLBx/RdlqkNv8QpryerhWBnUaVOfi1MzTd6MSZFGLBGLF0+TGvppIcYTSL'
```

To decrypt data using a key and IV, invoke the proxy like so:

```
curl -i -H 'content-type: text/plain' \
 -X POST \
 'https://ORGNAME-ENVNAME.apigee.net/aes-trial/decrypt2?key=2391652f01a99021d63789256e5d3d30&iv=c5b4039aadf01a1da13d04570da45265&source_encoding=base64' \
 -d 'rZjFqahLBx/RdlqkNv8QpryerhWBnUaVOfi1MzTd6MSZFGLBGLF0+TGvppIcYTSL'
```

## Bugs

None?

