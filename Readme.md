# AES Crypto callout

This directory contains the Java source code for 
a Java callout for Apigee Edge that does AES Encryption and Decryption of data or message payloads. 

This code is licensed under the Apache Source License v2.0. For information see the [LICENSE](LICENSE) file. 

## Using the Custom Policy

If you edit policies offline, copy the jar file for the custom policy, available in  callout/target/edge-callout-aes-encryptor-1.0-SNAPSHOT.jar  to your apiproxy/resources/java directory.  If you don't edit proxy bundles offline, upload that jar file into the API Proxy via the Edge API Proxy Editor .

When you use the policy to encrypt data, the resulting cipher-text can be decrypted by other systems. Likewise, the policy can decrypt cipher-text obtained from other systems. 
To do that, the encrypting and decrypting systems need to use the same key, the same AES mode, the same padding, and the same Initialization Vector (IV). Read up on AES if this is not clear to you.

The policy performs only AES crypto.


## Policy Configuration

The policy performs encryption or decryption of data, using the AES algorithm. There are a variety of options, which you can select using Properties in the configuration. Examples follow, but here's a quick summary:

- the policy uses as its source, the message.content. If you wish to encrypt something else, specify it with the source property
- The policy can use a key and initialization vector (IV) that you specify directly.
- Specify the key & iv encoded as either base64 or hex.
- Alternatively, specify a passphrase, and the policy will derive a key and IV via PBKDF2. If you specify the key and the passphrase, the key takes precedence. 
- Specify the mode (eg, CBC, OFB, CFB), and padding (PKCS5Padding, NoPadding).
- Specify a key strength in bits.  It defaults to 128-bit encryption.
- optionally encode (base64, hex) the output octet stream upon encryption
- optionally UTF-8 decode the output octet stream upon decryption

The policy has not been tested with AES modes other than CBC, OFB, or CFB.  

## Deriving Keys from Passphrases

[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) refers to Password-Based Key Derivation Function 2.  This is a standard described officially in [RFC 2898](https://www.ietf.org/rfc/rfc2898.txt).
It allows the derivation of a cryptographically strong key from a text password.

This custom policy can derive a key and IV from a passphrase using PBKDF2.

PBKDF2 requires a passphrase, a salt, a key strength, and a number of iterations. When configuring this policy to use PBKDF2, you must specify a passphrase. You may explicitly specify a salt, a desired output key strength in bits, and a number of iterations. The policy defaults those settings to the UTF-8 bytes for "Apigee-IloveAPIs", 128, and 128001, respectively, when they are not specified. 


## Example: Basic Encryption with a Passphrase, and Numerous Defaults

  ```xml
  <JavaCallout name="Java-AesEncrypt1">
    <Properties>
      <Property name='action'>encrypt</Property>
      <Property name='debug'>true</Property>
      <Property name='passphrase'>{request.queryparam.passphrase}</Property>
      <Property name='encode-result'>base64</Property>
    </Properties>
    <ClassName>com.dinochiesa.edgecallouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://edge-callout-aes-encryptor-1.0-SNAPSHOT.jar</ResourceURL>
  </JavaCallout>
  ```

No source property is specified, therefore this policy configuration will encrypt the message.content.
Specifying the passphrase means that a key and IV will be derived using PBKDF2. There is no pbkdf2-iterations property, so the policy will use its default value of 128001 iterations. There is no salt specified, so the policy uses its default of "Apigee-IloveAPIs". There's no key-strength property,  so the default of 128 bits applies.  There is no mode specified, so CBC is used. 
The result is encoded via base64. 

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
    <ClassName>com.dinochiesa.edgecallouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://edge-callout-aes-encryptor-1.0-SNAPSHOT.jar</ResourceURL>
  </JavaCallout>
  ```

No source property is specified, therefore this policy configuration will encrypt the message.content. Because there is a decode-source property, the policy will base64-decode the message.content to derive the cipher text. 

Specifying the passphrase means that a key and IV will be derived using PBKDF2. There is no pbkdf2-iterations property, so the policy will use its default value of 128001 iterations. There is no salt specified, so the policy uses its default of "Apigee-IloveAPIs". There's no key-strength property,  so the default of 128 bits applies.  There is no mode specified, so CBC is used.  
The result is decoded via UTF-8 to produce a plain string. (This only works if the original clear text was a plain string).


### Properties

These are the properties available on the policy:

| Property          | Description      |
|-------------------|------------------|
| action            | required. either "decrypt" or "encrypt".  |
| key               | optional. the cipher key. Can be 128 bits, 192 bits, or 256 bits. |
| iv                | optional. the cipher initialization vector. Must be specified if key is specified. Should be 128 bits. |
| decode-key        | optional. If specified, use either "hex" or "base64".|
| decode-iv         | optional. "hex" or "base64".|
| passphrase        | optional. a passphrase to use, dor deriving the key + IV via PBKDF2. Not used if key is specified. |
| pbkdf2-iterations | optional. the number of iterations to use in PBKDF2. (See [RFC 2898](https://www.ietf.org/rfc/rfc2898.txt))|
| salt              | optional. salt used for the PBKDF2. Used only when passphrase is specified. |
| key-strength      | optional. the strength of the key to derive. Applies only when passphrase is used. Defaults to 128 bits. |
| source            | name of the context variable containing the data to encrypt or decrypt. | 
| decode-source     | optional. either "hex" or "base64", to decode from a string to a octet stream |
| mode              | optional. CBC, CFB, or OFB. Defaults to CBC. |
| padding           | optional. either PKCS5Padding or NoPadding. If NoPadding is used the input must be a multiple of 8 bytes in length. |
| output            | optional. name of the variable in which to store the output. Defaults to crypto_output. |
| encode-result     | optional. Either hex or base64. The default is to not encode the result. |
| utf8-decode-result| optional. true or false. Applies only when action = decrypt. Decodes the byte[] array into a UTF-8 string. |
| debug             | optional. true or false. Emits extra context variables if true. Not for use in production. |



### Example: Basic Decryption with a Key and IV

  ```xml
  <JavaCallout name="Java-AesDecrypt1">
    <Properties>
      <Property name='action'>decrypt</Property>
      <Property name='decode-source'>base64</Property>
      <Property name='key'>{request.queryparam.key}</Property>
      <Property name='iv'>{request.queryparam.iv}</Property>
      <Property name='decode-key'>hex</Property>
      <Property name='decode-iv'>hex</Property>
      <Property name='utf8-decode-result'>true</Property>
    </Properties>
    <ClassName>com.dinochiesa.edgecallouts.AesCryptoCallout</ClassName>
    <ResourceURL>java://edge-callout-aes-encryptor-1.0-SNAPSHOT.jar</ResourceURL>
  </JavaCallout>
  ```

No source property is specified, therefore this policy configuration will encrypt the message.content. Because there is a decode-source property, the policy will base64-decode the message.content to derive the cipher text. 

Specifying the passphrase means that a key and IV will be derived using PBKDF2. There is no pbkdf2-iterations property, so the policy will use its default value of 128001 iterations. There is no salt specified, so the policy uses its default of "Apigee-IloveAPIs". There's no key-strength property,  so the default of 128 bits applies.  There is no mode specified, so CBC is used.  
The result is decoded via UTF-8 to produce a plain string. (This only works if the original clear text was a plain string).


## Notes on Usage

You can encrypt with a passphrase, but that means deriving a key from the passphrase with PBKDF2. Deriving a new key every time you use the policy will mean that performance will be sub-optimal at high load. It will perform better at load if you specify the key explicitly, and do not ask the policy to perform the calculations to derive the key. You can specify the key directly as a hex-encoded string.

One option to get the key is to call the policy once with a passphrase to encrypt, and thereby implicitly build the key and IV. The policy flow can then retrieve the derived key from context variables, and store the key in the Apigee Edge Vault for future use. Upon subsequent calls, the policy flow would retrieve the key & IV and call the policy with those retrieved values.  This is only a suggestion. 



## Bulding the Jar

You do not need to build the Jar in order to use the custom policy. The custom policy is ready to use, with policy configuration. 
You need to re-build the jar only if you want to modify the custom policy.

If you do wish to build the jar, you can use maven to do so. Before you run the build the first time, you need to download the Apigee Edge dependencies into your local maven repo.

Preparation, first time only: `./buildsetup.sh`

To build: `mvn clean package`

The Jar source code includes tests. 


## Build Dependencies 

* Apigee Edge expressions v1.0
* Apigee Edge message-flow v1.0
* Apache commons lang 2.6
* Apache commons codec 1.7
* Bouncy Castle 1.50

These jars are specified in the pom.xml file.

You do not need to upload any of these Jars to Apigee Edge with your policy.  They are all available in Apigee Edge already. 


