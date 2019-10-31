# AES Crypto callout

This directory contains the Java source code for
a Java callout for Apigee Edge that performs AES Encryption and Decryption of data or message payloads.

## License

This code is Copyright (c) 2017 Google LLC, and is released under the Apache Source License v2.0. For information see the [LICENSE](LICENSE) file.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## Using the Custom Policy

You do not need to build the Jar in order to use the custom policy.

When you use the policy to encrypt data, the resulting cipher-text can be decrypted by other systems. Likewise, the policy can decrypt cipher-text obtained from other systems.
To do that, the encrypting and decrypting systems need to use the same key, the same AES mode, the same padding, and the same Initialization Vector (IV). Read up on AES if this is not clear to you.

The policy performs only AES crypto.


## Policy Configuration

The policy performs encryption or decryption of data, using the AES algorithm. There are a variety of options, which you can select using Properties in the configuration. Examples follow, but here's a quick summary:

- the policy uses as its source, the message.content. If you wish to encrypt something else, specify it with the source property
- The policy can use a key and initialization vector (IV) that you specify directly.
- Specify the key & iv encoded as either base64 or hex.
- Alternatively, specify a passphrase, and the policy will derive a key and optionally the IV via [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2). If you specify the key and the passphrase, the key takes precedence.
- Specify the mode (eg, CBC, OFB, CFB), and padding (PKCS5Padding, NoPadding).
- Specify a key strength in bits.  It defaults to 128-bit encryption.
- optionally encode (base64, hex) the output octet stream upon encryption
- optionally UTF-8 decode the output octet stream upon decryption

The policy has not been tested with AES modes other than CBC, OFB, or CFB.

## Deriving Keys from Passphrases

[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) refers to Password-Based Key Derivation Function 2.  This is a standard described officially in [IETF RFC 2898](https://www.ietf.org/rfc/rfc2898.txt).
It allows the derivation of a cryptographically strong key from a text password.

This custom policy can derive a key and optionally, an IV, from a passphrase using PBKDF2.

PBKDF2 requires a passphrase, a salt, a key strength, and a number of iterations. When configuring this policy to use PBKDF2, you must specify a passphrase. You may explicitly specify a salt, a desired output key strength in bits, and a number of iterations. The policy defaults those settings to the UTF-8 bytes for "Apigee-IloveAPIs", 128, and 128001, respectively, when they are not specified.

Via the configuration, you can configure the policy to derive just a key, or both a key and IV.  The key is taken from the first N bits, where N may be 128, 192, or 256 as specified by the configurator. For 128 bits, it means the key will be an octet stream of length 16. If an IV is also needed, the policy will take the next 128 bits from the output of the PBKDF2 as the random IV. The IV for AES is always 128 bits; that is the block length of AES.

## Example: Basic Encryption with a Passphrase, and Numerous Defaults

  ```xml
  <JavaCallout name="Java-AesEncrypt1">
    <Properties>
      <Property name='action'>encrypt</Property>
      <Property name='debug'>true</Property>
      <Property name='passphrase'>{request.queryparam.passphrase}</Property>
      <Property name='encode-result'>base64</Property>
    </Properties>
    <ClassName>com.google.apigee.edgecallouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://edge-callout-aes-crypto-20191030.jar</ResourceURL>
  </JavaCallout>
  ```

Here's what will happen with this policy configuration:

* the action is encrypt, so the policy will encrypt
* No source property is specified, therefore this policy will encrypt the message.content.
* Specifying the passphrase means that a key and IV will be derived using PBKDF2.
* There is no pbkdf2-iterations property, so the policy will use its default value of 128001 iterations.
* There is no salt specified, so the policy uses its default of "Apigee-IloveAPIs".
* There's no key-strength property, so the default of 128 bits applies.
* There is no mode specified, so CBC is used.
* There is no padding specified, so PKCS5Padding is used.
* The result is encoded via base64.

To decrypt, either within Apigee Edge with this policy, or using some other system, the decryptor needs to use the same passphrase, the same PBKDF2 iterations and the same PBKDF2 salt, in order to arrive at the key and IV.


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
    <ClassName>com.google.apigee.edgecallouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://edge-callout-aes-crypto-20191030.jar</ResourceURL>
  </JavaCallout>
  ```

What will this policy configuration do?:

* the action is decrypt, so the policy will decrypt
* No source property is specified, therefore this policy will decrypt the message.content.
* Because there is a decode-source property, 'base64', the policy will base64-decode the message.content to derive the cipher text.
* Specifying the passphrase means that a key and IV will be derived using PBKDF2, with the defaults the same as in the prior example.
* There is no mode or padding specified, so AES/CBC/PKCS5Padding is used.
* The result is decoded via UTF-8 to produce a plain string. (Obviously, this will work only if the original clear text was a plain string).



### Full Properties List

These are the properties available on the policy:

| Property          | Description                                                                                                                                       |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| action            | required. either "decrypt" or "encrypt".                                                                                                          |
| key               | optional. the cipher key. Can be 128 bits, 192 bits, or 256 bits. if not specified, must use passphrase.                                          |
| iv                | optional. the cipher initialization vector. Required if key is specified. Should be 128 bits.                                                     |
| decode-key        | optional. If specified, use either "hex" or "base64".                                                                                             |
| decode-iv         | optional. "hex" or "base64".                                                                                                                      |
| passphrase        | optional. a passphrase to use, for deriving the key + IV via PBKDF2. Not used if key is specified.                                                |
| pbkdf2-iterations | optional. the number of iterations to use in PBKDF2. (See [IETF RFC 2898](https://www.ietf.org/rfc/rfc2898.txt)) Used only with passphrase.       |
| salt              | optional. salt used for the PBKDF2. Used only when passphrase is specified.                                                                       |
| key-strength      | optional. the strength of the key to derive. Applies only when passphrase is used. Defaults to 128 bits.                                          |
| source            | optional. name of the context variable containing the data to encrypt or decrypt. Do not surround in curly braces. Defaults to `message.content`. |
| decode-source     | optional. either "hex" or "base64", to decode from a string to a octet stream.                                                                    |
| mode              | optional. CBC, CFB, or OFB. Defaults to CBC.                                                                                                      |
| padding           | optional. either PKCS5Padding or NoPadding. If NoPadding is used the input must be a multiple of 8 bytes in length.                               |
| output            | optional. name of the variable in which to store the output. Defaults to crypto_output.                                                           |
| encode-result     | optional. Either hex or base64. The default is to not encode the result. The base64 encoding is url-safe.                                         |
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
    <ClassName>com.google.apigee.edgecallouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://edge-callout-aes-crypto-20191030.jar</ResourceURL>
  </JavaCallout>
  ```

What will this policy configuration do?

* the action tells the policy to decrypt
* The source property is specified, therefore this policy will decrypt the value found in the context variable "ciphertext".
* Because there is a decode-source property, the policy will base64-decode the value of "ciphertext" to derive the actual byte array for the ciphertext.
* Specifying the key and iv, rather than a passphrase means that the policy will use these data directly. There is no PBKDF2 iteration. The key and the iv are both passed as hex-encoded strings, and the policy decodes them accordingly, based on decode-hex and decode-iv.
* no mode or padding specified, so AES/CBC/PKCS5Padding is used.
* The result is decoded via UTF-8 to produce a plain string. (This only works if the original clear text was a plain string).


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
    <ClassName>com.google.apigee.edgecallouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://edge-callout-aes-crypto-20191030.jar</ResourceURL>
  </JavaCallout>
  ```

Here's what will happen with this configuration:

* The action tells the policy to encrypt
* No source property is specified, therefore this policy configuration will encrypt the message.content.
* Specifying the passphrase means that a key and IV will be derived using PBKDF2.
* The PBKDF2 will use 65000 and VarietyIsTheSpiceOfLife for pbkdf2-iterations and salt. Only the first 128 bits of salt are used!
* a key-strength of 256 bits will be used.
* The AES mode will be CFB.
* There is no padding specified, so PKCS5Padding is used.
* The resulting ciphertext byte array is encoded into a string via base64.



## Example: 256-bit AES(CFB) Encryption with a Passphrase, and a specific IV

  ```xml
  <JavaCallout name="Java-AesEncrypt1">
    <Properties>
      <Property name='action'>encrypt</Property>
      <Property name='debug'>true</Property>
      <Property name='passphrase'>{request.queryparam.passphrase}</Property>
      <Property name='pbkdf2-iterations'>65000</Property>
      <Property name='salt'>VarietyIsTheSpiceOfLife</Property>
      <Property name='key-strength'>256</Property>
      <Property name='iv'>00000000000000000000000000000000</Property>
      <Property name='decode-iv'>hex</Property>
      <Property name='mode'>CFB</Property>
      <Property name='encode-result'>base64</Property>
    </Properties>
    <ClassName>com.google.apigee.edgecallouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://edge-callout-aes-crypto-20191030.jar</ResourceURL>
  </JavaCallout>
  ```

This policy works like the prior example, except, rather than deriving both the key and IV, the policy derives just the key using PBKDF2. The IV is always set to a stream of 16 zeros.


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
* you use a `decode-*` parameter that is neither hex nor base64
* you specify a `decode-iv` or `decode-key` of `hex`, and the iv or key is not a HEX-encoded string. Or, you specify `base64` and your iv or key is not a base64-encoded string.
* some other configuration value is null or invalid


## Notes on Usage and Efficiency

You can encrypt with a passphrase, but that means deriving a key from the passphrase with PBKDF2. Deriving a new key every time you use the policy will mean that performance will be sub-optimal at high load. It will perform better at load if you specify the key explicitly, and do not ask the policy to perform the calculations to derive the key. You can specify the key directly as a hex-encoded string.

One option to get the key is to call the policy once with a passphrase to encrypt, and thereby implicitly build the key and IV. The policy flow can then retrieve the derived key from context variables, and store the key in the Apigee Edge Encrypted KVM for future use. Upon subsequent calls, the policy flow would retrieve the key & IV from the encrypted KVM, and call the policy with those retrieved values.  This is only a suggestion.


## On Key Strength

If you use the Oracle JDK to run this policy, either for tests during a build, or in actual deployment, 256-bit encryption requires the Unlimited Strength JCE from Oracle. (For example, this is [the download for Java 8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html) )

Without the Unlimited Strength JCE, you may get an exception while running tests or when trying to initiate a cipher with a key greater than 128 bits:

```
java.security.InvalidKeyException: Illegal key size
        at javax.crypto.Cipher.checkCryptoPerm(Cipher.java:1039)
        ....
```

When run in an Apigee Edge Message Processor, this will cause the crypto_error context variable to be set, with the message "Illegal key size".

See [this article](http://stackoverflow.com/a/6481658/48082) for more information and some discussion on this exception.

If you use OpenJDK to run the tests, or to deploy the Policy, then it's not an issue. (The OPDK version of Apigee Edge runs on OpenJDK.)  In that JDK, there's no restriction on key strength.


## Building the Jar

You do not need to build the Jar in order to use the custom policy. The custom policy is
ready to use, with policy configuration. You need to re-build the jar only if you want
to modify the behavior of the custom policy. Before you do that, be sure you understand
all the configuration options - the policy may be usable for you without modification.

If you do wish to build the jar, you can use [maven](https://maven.apache.org/download.cgi) to do so. The build requires JDK8. Before you run the build the first time, you need to download the Apigee Edge dependencies into your local maven repo.

Preparation, first time only: `./buildsetup.sh`

To build: `mvn clean package`

The Jar source code includes tests.

If you edit policies offline, copy [the jar file for the custom policy](callout/target/edge-callout-aes-crypto-20191030.jar)  to your apiproxy/resources/java directory.  If you don't edit proxy bundles offline, upload that jar file into the API Proxy via the Edge API Proxy Editor .


## Author

Dino Chiesa
godino@google.com
