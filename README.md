 # AES Crypto callout

This directory contains the Java source code for two Java callouts for Apigee:

1. AesCryptoCallout - performs AES Encryption and Decryption of data or message payloads.
2. PBKDF2 - performs PBKDF2 key derivation from a passphrase.

## License

This code is Copyright (c) 2017-2021 Google LLC, and is released under the
Apache Source License v2.0. For information see the [LICENSE](LICENSE) file.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## Using the Custom Policy

You do not need to build the Jar in order to use the custom policies.

When you use the AesCryptoCallout policy to encrypt data, the resulting cipher-text can be
decrypted by other systems. Likewise, the policy can decrypt cipher-text
obtained from other systems. To do that, the encrypting and decrypting systems
need to use the same key, the same AES mode, the same padding, and the same
Initialization Vector (IV). Read up on AES if this is not clear to you.

When you use the PBKDF2 policy to generate keys, the resulting key can be used for anything you like.

## Policy Configuration: PBKDF2

[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) refers to Password-Based Key
Derivation Function 2. This is a standard described officially in [IETF RFC
2898](https://www.ietf.org/rfc/rfc2898.txt). It allows the derivation of a
cryptographically strong key from a text password.

The PBKDF2 policy derives keys from passphrases, following the
[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)
algorithm.

PBKDF2 requires as input:
- a passphrase,
- a salt,
- a desired output key length in bytes (aka dklen),
- a number of iterations, and
- a pseudo-random function (PRF).  This is usually a keyed MAC, aka HMAC.

When using the PBKDF2 policy, you must specify all of those inputs
explicitly. There are no defaults. Some additional information:

- The policy decodes the salt value via UTF-8 by default. Specify `decode-salt` as one of
  {`base16`, `base64` or `base64url`} to tell the policy to decode the salt string
  differently.
- The output key length must be no more than 4096 bytes.
- The maximum number of iterations is 2560000. Using a large value for the iteration count will result in
significant computation time at runtime.
- This policy supports `HMAC-SHA1` and `HMAC-SHA256` as the PRF.


The policy emits the output, a passphrase-derived key, into variables:
`pbkdf2_output_b16`, `pbkdf2_output_b64`, and `pbkdf2_output_b64url` for the
base16, base64 and base64url-encoded versions of the result, respectively. They
all represent the same value; a byte array of length `dklen`. They are simply
encoded differently.

## Example PBKDF2

```xml
<JavaCallout name="Java-PBKDF2">
  <Properties>
    <Property name='passphrase'>Melo_123</Property>
    <Property name='iterations'>30000</Property>
    <Property name='dklen'>32</Property>
    <Property name='salt'>TSKRGzW5dWMC</Property>
    <Property name='prf'>HMAC-SHA256</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.PBKDF2</ClassName>
  <ResourceURL>java://apigee-callout-aes-crypto-20211122a.jar</ResourceURL>
</JavaCallout>
```

When the policy runs with this configuration, it will set these context
variables:

| name  | value  |
| ---- | ------ |
| `pbkdf2_output_b16` | 79f59ed6ae7c63ad9a2d6caf9fb3293652386c358f4072b6c9483e8f13ccb0a4 |
| `pbkdf2_output_b64url` | efWe1q58Y62aLWyvn7MpNlI4bDWPQHK2yUg-jxPMsKQ= |
| `pbkdf2_output_b64` | efWe1q58Y62aLWyvn7MpNlI4bDWPQHK2yUg+jxPMsKQ= |


The output value is suitable for use as symmetric key material for some other crypto
processing that requires a symmetric key.

If you also set the `expected` property, like this:

```xml
<JavaCallout name="Java-PBKDF2">
  <Properties>
    <Property name='passphrase'>Melo_123</Property>
    <Property name='iterations'>30000</Property>
    <Property name='dklen'>32</Property>
    <Property name='salt'>TSKRGzW5dWMC</Property>
    <Property name='prf'>HMAC-SHA256</Property>
    <Property name='expected'>{variable-containing-expected-value}</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.PBKDF2</ClassName>
  <ResourceURL>java://apigee-callout-aes-crypto-20211122a.jar</ResourceURL>
</JavaCallout>
```

...then the policy will check the computed value against your expected value. The
policy assumes the expected value is encoded with base64. If the expected value
does not match the computed value, then the policy will set the string "no
match" in the `pbkdf2_error` context variable.

You would need to check this with a `Condition` element on a subsequent step in
the flow.

When you use the property `expected`, if you also specify `raise-fault-on-no-match` as true, like this:

```xml
<JavaCallout name="Java-PBKDF2">
  <Properties>
    <Property name='passphrase'>Melo_123</Property>
    <Property name='iterations'>30000</Property>
    <Property name='dklen'>32</Property>
    <Property name='salt'>TSKRGzW5dWMC</Property>
    <Property name='prf'>HMAC-SHA256</Property>
    <Property name='expected'>{variable-containing-expected-value}</Property>
    <Property name='raise-fault-on-no-match'>true</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.PBKDF2</ClassName>
  <ResourceURL>java://apigee-callout-aes-crypto-20211122a.jar</ResourceURL>
</JavaCallout>
```

...then the policy will also raise a fault when the expected value does not
match the computed value.  You can then handle this in a `FaultRule`.


## Policy: AesCrypto

The AesCryptoCallout policy performs encryption or decryption of data, using the AES
algorithm. There are a variety of options, which you can select using Properties
in the configuration. Examples follow, but here's a quick summary:

- the policy uses as its source, the message.content. If you wish to encrypt something else, specify it with the source property
- The policy can use a key and initialization vector (IV) that you specify
  directly. Specify the key & iv encoded as either base64, base64url, or base16.
- Alternatively, specify a passphrase, and the policy will derive a key and
  optionally the IV via [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2). If you
  specify the key and the passphrase, the key takes precedence.
- Or, you can ask the policy to generate a key and IV randomly.
- Specify the mode (eg, CBC, OFB, CFB, GCM), and padding (PKCS5Padding, NoPadding).
- Specify a key strength in bits.  It defaults to 128-bit encryption.
- optionally encode (base64, base64url, base16) the output octet stream upon encryption
- optionally UTF-8 decode the output octet stream upon decryption

The policy has not been tested with AES modes other than GCM, CBC, OFB, or CFB.

## AesCrypto: Deriving Keys from Passphrases

The AesCrypto custom policy can derive a key and optionally, an IV, from a passphrase using PBKDF2.

This callout supports `HMAC-SHA1` and `HMAC-SHA256` as the PRF. The maximum number of iterations is 2560000.

When configuring the AesCrypto policy to use PBKDF2, you must specify a
passphrase. You may optionally specify a salt, a desired output key strength in
bits, a number of iterations, and/or a PRF. The policy defaults those settings to the
UTF-8 bytes for "Apigee-IloveAPIs", 128, 128001, and HMAC-SHA1, respectively, when they are
not specified.

Via the configuration, you can configure the policy to derive just a key, or
both a key and IV. The key is taken from the first N bits, where N may be 128,
192, or 256 as specified by the configurator. For 128 bits, it means the key
will be an octet stream of length 16. If an IV is also needed, the policy will
take the next 128 bits from the output of the PBKDF2 as the random IV. The IV
for AES is always 128 bits; that is the block length of AES.

To tell the policy to generate the key and use a static IV, specify the iv explicitly.

## Example: Basic Encryption with a Passphrase, and Numerous Defaults

  ```xml
  <JavaCallout name="Java-AesEncrypt1">
    <Properties>
      <Property name='action'>encrypt</Property>
      <Property name='debug'>true</Property>
      <Property name='passphrase'>{request.queryparam.passphrase}</Property>
      <Property name='encode-result'>base64</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://apigee-callout-aes-crypto-20211122a.jar</ResourceURL>
  </JavaCallout>
  ```

Here's what will happen with this policy configuration:

* the `action` is encrypt, so the policy will encrypt
* No `source` property is specified, therefore this policy will encrypt the message.content.
* Specifying the `passphrase` means that a key and IV will be derived using PBKDF2.
* There is no `pbkdf2-iterations` property, so the policy will use its default value of 128001 iterations.
* There is no `salt` specified, so the policy uses its default of "Apigee-IloveAPIs".
* There's no `key-strength` property, so the default of 128 bits applies.
* There is no `mode` specified, so the policy uses `CBC`.
* There is no `padding` specified, so the policy uses `PKCS5Padding`.
* The policy encode the resulting cihertext via base64 and places it into `crypto_output`.

To decrypt the result of that, either within Apigee Edge with this policy, or
using some other system, the decryptor needs to use the same passphrase, the
same PBKDF2 iterations and the same PBKDF2 salt, in order to arrive at the key
and IV. And then the same AES mode, which here has defaulted to CBC.


### Example: Basic Decryption with a Passphrase

  ```xml
  <JavaCallout name="Java-AesDecrypt1">
    <Properties>
      <Property name='action'>decrypt</Property>
      <Property name='debug'>true</Property>
      <Property name='decode-source'>base64</Property>
      <Property name='passphrase'>{request.queryparam.passphrase}</Property>
      <Property name='utf8-decode-result'>true</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://apigee-callout-aes-crypto-20211122a.jar</ResourceURL>
  </JavaCallout>
  ```

What will this policy configuration do?:

* the `action` is decrypt, so the policy will decrypt
* No `source` property is specified, therefore this policy will decrypt the message.content.
* Because there is a `decode-source` property, 'base64', the policy will base64-decode the `message.content` to derive the cipher text.
* Specifying the `passphrase` tells the policy to derive a key and IV using PBKDF2, with the defaults for iterations and salt the same as in the prior example.
* There is no `mode` or `padding` specified, so the policy will use `CBC` and `PKCS5Padding`.
* The policy decodes the result via UTF-8 to produce a plain string. Obviously, this will work only if the original clear text was a plain string!


### Full Properties List

These are the properties available on the policy:

| Property          | Description                                                                                                                                       |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| action            | required. either `decrypt` or `encrypt`.                                                                                                          |
| key               | optional. the cipher key, of length 128 bits, 192 bits, or 256 bits. If not specified, must specify the `passphrase` property.                    |
| iv                | optional. the cipher initialization vector. Required if key is specified. Should be 128 bits in length.                                           |
| generate-key      | optional. Boolean. If true, the policy will generate a key and IV and emit them as context variables (encoded). Not used if the key is specified. Sensible only if action=encrypt. |
| decode-key        | optional. One of: {`base64`, `base64url`, `base16`, `none`}.                                                                                      |
| decode-iv         | optional. One of: {`base64`, `base64url`, `base16`, `none`}.                                                                                      |
| passphrase        | optional. a passphrase to use, for deriving the key + IV via PBKDF2. Not used if key is specified.                                                |
| pbkdf2-iterations | optional. the number of iterations to use in PBKDF2. (See [IETF RFC 2898](https://www.ietf.org/rfc/rfc2898.txt)) Used only with passphrase.       |
| pbkdf2-prf        | optional. PRF used for the PBKDF2. either `HMAC-SHA1` or `HMAC-SHA256`. Defaults to `HMAC-SHA1`.                                                  |
| salt              | optional. salt used for the PBKDF2. Used only when `passphrase` is specified. Defaults to "Apigee-IloveAPIs" if not specified.                    |
| key-strength      | optional. the strength of the key to derive. Applies only when passphrase is present. Defaults to 128 bits.                                       |
| source            | optional. name of the context variable containing the data to encrypt or decrypt. Do not surround in curly braces. Defaults to `message.content`. |
| decode-source     | optional. One of: {`base64`, `base64url`, `base16`, `none`}, to decode from a string to a octet stream.                                           |
| mode              | optional. `CBC`, `CFB`, `OFB`, or `GCM`. Defaults to `CBC`.                                                                                       |
| padding           | optional. either `PKCS5Padding` or `NoPadding`. If the value is `NoPadding`, the input must be a multiple of 8 bytes in length.                   |
| aad               | optional. optional. Used only when mode=GCM. The "Additional Authenticated Data". Must specify this for encrypt or decrypt.                       |
| decode-aad        | optional. One of: {`base64`, `base64url`, `base16`, `none`}, to decode from a string to a octet stream.                                           |
| tag               | optional. optional. Used only when mode=GCM, and action=decrypt. The authentication tag emitted during encryption.                                |
| decode-tag        | optional. One of: {`base64`, `base64url`, `base16`, `none`}, to decode from a string to a octet stream.                                           |
| output            | optional. name of the variable in which to store the output. Defaults to `crypto_output`.                                                         |
| encode-result     | optional. One of: {`base64`, `base64url`, `base16`}. The default is to not encode the result.                                                           |
| utf8-decode-result| optional. true or false. Applies only when action = decrypt. Decodes the byte[] array into a UTF-8 string.                                        |
| debug             | optional. true or false. Emits extra context variables if true. Not for use in production.                                                        |



### Example: Basic Decryption with a Key and IV

  ```xml
  <JavaCallout name="Java-AesDecrypt1">
    <Properties>
      <Property name='action'>decrypt</Property>
      <Property name='source'>ciphertext</Property>
      <Property name='decode-source'>base64</Property>
      <Property name='key'>{request.queryparam.key}</Property>
      <Property name='iv'>{request.queryparam.iv}</Property>
      <Property name='decode-key'>hex</Property>
      <Property name='decode-iv'>hex</Property>
      <Property name='utf8-decode-result'>true</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://apigee-callout-aes-crypto-20211122a.jar</ResourceURL>
  </JavaCallout>
  ```

What will this policy configuration do?

* the `action` tells the policy to decrypt
* The `source` property is specified, therefore this policy will decrypt the value found in the context variable "ciphertext".
* Because there is a `decode-source` property, the policy will base64-decode the value of "ciphertext" to derive the actual byte array for the ciphertext.
* Specifying the `key` and `iv`, rather than a `passphrase` means that the policy will use these data directly. There is no PBKDF2 iteration. The key and the iv are both passed as hex-encoded strings, and the policy decodes them accordingly, based on `decode-hex` and `decode-iv`.
* no `mode` or `padding` specified, so the policy uses `AES/CBC/PKCS5Padding`.
* The callout decodes the result via UTF-8 to produce a plain string. Of course, This will work only if the original clear text was a plain string!
* Because there is no `output` property specified, the callout places the result by default into the variable `crypto_output`.


## Example: 256-bit Encryption with a Passphrase, and different settings

  ```xml
  <JavaCallout name="Java-AesEncrypt1">
    <Properties>
      <Property name='action'>encrypt</Property>
      <Property name='debug'>true</Property>
      <Property name='passphrase'>{request.queryparam.passphrase}</Property>
      <Property name='pbkdf2-iterations'>65000</Property>
      <Property name='salt'>VarietyIsTheSpiceOfLife</Property>
      <Property name='key-strength'>256</Property>
      <Property name='mode'>CFB</Property>
      <Property name='encode-result'>base64</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://apigee-callout-aes-crypto-20211122a.jar</ResourceURL>
  </JavaCallout>
  ```

Here's what will happen with this configuration:

* The `action` tells the policy to encrypt
* No `source` property is specified in the configuration, therefore the policy will encrypt the message.content.
* Specifying the `passphrase` tells the policy to derive a key and IV from the passphrase using PBKDF2.
* The PBKDF2 logic will use 65000 and VarietyIsTheSpiceOfLife for pbkdf2-iterations and salt. The Salt will be the bytes resulting from UTF-8 encoding the salt string. Only the first 128 bits of salt are used!
* a key-strength of 256 bits will be used.
* The `mode` property tells the policy to use the AES mode `CFB`.
* There is no `padding` specified, so the policy uses `PKCS5Padding`.
* Because of the `encode-result` property, the policy encodes resulting ciphertext byte array into a string via base64.
* Because there is no `output` property specified, the callout places the result by default into the variable `crypto_output`.


## Example: 256-bit AES(CFB) Encryption with a key derived from a specific Passphrase, and a specific IV

  ```xml
  <JavaCallout name="Java-AesEncrypt1">
    <Properties>
      <Property name='action'>encrypt</Property>
      <Property name='debug'>true</Property>
      <Property name='passphrase'>{request.queryparam.passphrase}</Property>
      <Property name='pbkdf2-iterations'>65000</Property>
      <Property name='pbkdf2-prf'>HMAC-SHA256</Property>
      <Property name='salt'>VarietyIsTheSpiceOfLife</Property>
      <Property name='key-strength'>256</Property>
      <Property name='iv'>00000000000000000000000000000000</Property>
      <Property name='decode-iv'>hex</Property>
      <Property name='mode'>CFB</Property>
      <Property name='encode-result'>base64</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://apigee-callout-aes-crypto-20211122a.jar</ResourceURL>
  </JavaCallout>
  ```

This policy works like the prior example, except, rather than deriving both the
key and IV, the policy derives just the key using PBKDF2, and uses HMAC-SHA256
for the PRF when deriving the key. The IV is always set to a stream of 16 zeros.

## Example: 128-bit AES GCM decyption

For this you must specify an `aad`, and a `tag`, along with a `key` and `iv`.

  ```xml
  <JavaCallout name="Java-AesEncrypt1">
    <Properties>
      <Property name='action'>decrypt</Property>
      <Property name='debug'>true</Property>
      <Property name='mode'>GCM</Property>
      <Property name="padding">NoPadding</Property>
      <Property name='key'>385f9fd4cba017c159956276036545b0</Property>
      <Property name='decode-key'>base16</Property>
      <Property name="iv">mRqogt0pxtPdgyjt</Property>
      <Property name="decode-iv">base64url</Property>
      <Property name="source">ciphertext</Property>
      <Property name="decode-source">base64url</Property>
      <Property name="aad">eyJ0eXAiOiJKV1QiLCJoZHIxIjoxMjMsImVuYyI6IkExMjhHQ00iLCJoZHIyIjp0cnVlLCJhbGciOiJSU0EtT0FFUC0yNTYifQ</Property>
      <Property name="tag">ESdhCa_eqd2FaI5e5IH2xQ</Property>
      <Property name="decode-tag">base64url</Property>
      <Property name='utf8-decode-result'>true</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://apigee-callout-aes-crypto-20211122a.jar</ResourceURL>
  </JavaCallout>
  ```

If the context variable `ciphertext` contains the value
`73XlhsvhcsaIFJUrqZFyf0Hjgxx9A-rbPWoIdsup-ScsXuqO6RevhNdjBg`, this policy will
decrypt the result and emit `{"sub":"dino@example.org","iat":1555976853}`.

This decryption is the same that is used for encrypting payloads in
[JWE](https://tools.ietf.org/html/rfc7516). This example is AES 128 bit key,
corresponding to a JWT enc="A128GCM". For A256GCM, you just need to supply a
larger 256-bit key.  Everything else is the same.



## Detecting Success and Errors

The policy will return ABORT and set the context variable `crypto_error` if there has been any error at runtime. Your proxy bundles can check this variable in `FaultRules`.

Errors can result at runtime if:

* you do not specify an `action` property, or the `action` is neither `encrypt` nor `decrypt`
* you pass a key of invalid length (not 128, 192, or 256 bits)
* you pass a `key-strength` that is not 128, 192, or 256
* you pass an `iv` of invalid length (not 128 bits)
* you specify a `mode` that is invalid (not `CBC`, `CFB`, `OFB`)
* you specify a `padding` that is neither `NoPadding` nor `PKCS5Padding`
* you specify `NoPadding` and your source (cleartext when encrypting) is not a multiple of 16-bytes in length
* you specify `action` = decrypt, and regardless of padding, your source is not a multiple of 16-bytes in length
* you use a `decode-*` parameter that is not one of: {base64, base64url, base16}
* you specify a `decode-iv` or `decode-key` of `base16`, and the iv or key is
  not a Base16-encoded string. Or, you specify `base64` and your iv or key is
  not a base64-encoded string. etc.
* some other configuration value is null or invalid


## Regarding the Passphrase and Efficiency

You can encrypt with a passphrase, but that means deriving a key from the
passphrase with PBKDF2. Deriving a new key every time you use the policy will
mean that performance will be sub-optimal at high load. It's not harmful to have
the policy derive the key each time through PBKDF2, but it does consume compute
resources, and that requires time. The policy will perform better at load if
you specify the key explicitly, and do not ask the policy to perform the
calculations to derive the key. You can specify the key directly as a
hex-encoded string.

One option for avoiding the repetitive generation of the key via PBKDF2: call
the policy once with a passphrase to encrypt, and thereby implicitly build the
key and IV. The policy flow can then retrieve the derived key from context
variables, and store the key in the Apigee Encrypted KVM for future use. Then
you can modify the policy configuration to accept not a passphrase, but an
encoded key and IV; you would need to extend the policy flow to retrieve the key
& IV from the encrypted KVM, and call the policy with those retrieved
values. You could make this automatic using conditions in the flow.  You can
alternatively derive the key and IV from some external program that implements
PBKDF2, and store that result in the encrypted KVM. Then always configure the
policy to accept an encoded key and IV, rather than a passphrase.

## About GCM

Galois Counter Mode, or GCM, allows the use of "Additional Authenticated Data",
also known as AAD, or an authentication tag. When an actor encrypts a byte
stream with AES / GCM, the actor also specifies an "Additional Authenticated
Data", or AAD. This is not a secret, but is used in the encryption. In theory,
this can be from 0 to 2^64 bits.

With this policy, for encryption you use the `aad` property to specify the AAD.

The resulting Authentication _tag_ (an output of AES / GCM) is appended to the
ciphertext. By default, this policy emits 128 bits of tag.  If you want to
affect the size of the tag, you can specify the `tag-bits` property during
encryption.

For decryption, the actor must again supply the AAD - remember, it's not a
secret. And the actor must supply the authentication tag, if it is not already
appended to the ciphertext. Do this with the tag parameter.

Whether decrypting or encrypting a byte stream with AES / GCM, there is no meaning
to padding, so NoPadding is equivalent to PKCS5Padding.


## On Key Strength

If you use the Oracle JDK to run this policy, either for tests during a build, or in actual deployment, 256-bit encryption requires the Unlimited Strength JCE from Oracle. (For example, this is [the download for Java 8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html) )

Without the Unlimited Strength JCE, you may get an exception while running tests
or when trying to initiate a cipher with a key greater than 128 bits:

```
java.security.InvalidKeyException: Illegal key size
        at javax.crypto.Cipher.checkCryptoPerm(Cipher.java:1039)
        ....
```

When run in an Apigee Edge Message Processor, this will cause the crypto_error
context variable to be set, with the message "Illegal key size".

See [this article](http://stackoverflow.com/a/6481658/48082) for more
information and some discussion on this exception.

If you use OpenJDK to run the tests, or to deploy the Policy, then it's not an
issue. (The OPDK version of Apigee Edge runs on OpenJDK.)  In that JDK, there's
no restriction on key strength.


## Building the Jar

You do not need to build the Jar in order to use the custom policy. The custom policy is
ready to use, with policy configuration. You need to re-build the jar only if you want
to modify the behavior of the custom policy. Before you do that, be sure you understand
all the configuration options - the policy may be usable for you without modification.

If you do wish to build the jar, you can use
[maven](https://maven.apache.org/download.cgi) to do so. The build requires
JDK8. Before you run the build the first time, you need to download the Apigee
Edge dependencies into your local maven repo.

Preparation, first time only: `./buildsetup.sh`

To build: `mvn clean package`

The Jar source code includes tests.

If you edit policies offline, copy [the jar file for the custom
policy](callout/target/apigee-callout-aes-crypto-20211122a.jar) to your
apiproxy/resources/java directory.  If you don't edit proxy bundles offline,
upload that jar file into the API Proxy via the Edge API Proxy Editor .


## Bugs

- There is no example proxy for the PBKDF2 callout.


## Author

Dino Chiesa
godino@google.com
