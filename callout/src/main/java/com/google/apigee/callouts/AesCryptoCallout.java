// AesCryptoCallout.java
//
// This is the main callout class for the AES Crypto custom policy for Apigee Edge.
// For full details see the Readme accompanying this source file.
//
// Copyright (c) 2016 Apigee Corp, 2017-2021 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// @author: Dino Chiesa
//

package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.encoding.Base16;
import com.google.apigee.util.PasswordUtil;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@IOIntensive
public class AesCryptoCallout extends CalloutBase implements Execution {
  private static final int AES_IV_LENGTH = 128;
  private static final int GCM_AUTH_DEFAULT_TAG_BITS = 128;
  private static final String defaultKeyStrength = "128";
  private static final String defaultPbkdf2Iterations = "128001";
  private static final int maxPbkdf2Iterations = 2560000;
  private static final int minPbkdf2Iterations = 1;
  private static final String defaultCipherName = "AES";
  private static final String defaultCryptoMode = "CBC";
  private static final String defaultCryptoPadding = "PKCS5PADDING";
  private static final String defaultOutputVarSuffix = "output";
  private static final String TRUE = "true";
  private static final byte[] defaultSalt = "Apigee-IloveAPIs".getBytes(StandardCharsets.UTF_8);
  private static final SecureRandom secureRandom = new SecureRandom();

  private static Pattern fullCipherPattern =
      Pattern.compile(
          "^(AES)/(CBC|ECB|CFB|GCM)/(NoPadding|PKCS5Padding)$", Pattern.CASE_INSENSITIVE);
  private static Pattern cipherNamePattern = Pattern.compile("^(AES)$", Pattern.CASE_INSENSITIVE);
  private static Pattern fullGCMCipherPattern =
      Pattern.compile("^(AES)/GCM/(NoPadding|PKCS5Padding)$", Pattern.CASE_INSENSITIVE);

  private static final String defaultGcmAadLength = "16";
  // private static final int GCM_DEFAULT_TAG_BYTES = 16;
  private static final int GCM_MIN_TAG_BYTES = 0;
  private static final int GCM_MAX_TAG_BYTES = 2048;

  public AesCryptoCallout(Map properties) {
    super(properties);
  }

  String getVarPrefix() {
    return "crypto_";
  };

  enum CryptoAction {
    DECRYPT,
    ENCRYPT
  };

  private String getSourceVar() {
    String source = this.properties.get("source");
    if (source == null || source.equals("")) {
      // by default, get the content of the message (either request or response)
      return "message.content";
    }
    return source;
  }

  private byte[] getIv(MessageContext msgCtxt) throws Exception {
    return _getByteArrayProperty(msgCtxt, "iv");
  }

  private byte[] getAad(MessageContext msgCtxt) throws Exception {
    return _getByteArrayProperty(msgCtxt, "aad");
  }

  private byte[] getTag(MessageContext msgCtxt) throws Exception {
    return _getByteArrayProperty(msgCtxt, "tag");
  }

  private byte[] getKey(MessageContext msgCtxt) throws Exception {
    return _getByteArrayProperty(msgCtxt, "key");
  }

  private byte[] getSalt(MessageContext msgCtxt) throws Exception {
    byte[] result = _getByteArrayProperty(msgCtxt, "salt");
    return (result == null) ? defaultSalt : result;
  }

  private EncodingType getEncodeResult(MessageContext msgCtxt) throws Exception {
    return _getEncodingTypeProperty(msgCtxt, "encode-result");
  }

  private CryptoAction getAction(MessageContext msgCtxt) throws Exception {
    String action = this.properties.get("action");
    if (action != null) action = action.trim();
    if (action == null || action.equals("")) {
      throw new IllegalStateException("specify an action.");
    }
    action = resolveVariableReferences(action, msgCtxt);
    return CryptoAction.valueOf(action.toUpperCase());
  }

  private PasswordUtil.PRF getPseudoRandomFunction(MessageContext msgCtxt) throws Exception {
    String prfString = this.properties.get("pbkdf2-prf");
    if (prfString != null) prfString = prfString.trim();
    if (prfString == null || prfString.equals("")) {
      return PasswordUtil.PRF.HMACSHA1;
    }
    prfString = resolveVariableReferences(prfString, msgCtxt);
    return PasswordUtil.PRF.valueOf(prfString.toUpperCase().replaceAll("-", ""));
  }

  private int getKeyStrength(MessageContext msgCtxt) throws Exception {
    String v = _getStringProp(msgCtxt, "key-strength", defaultKeyStrength);
    if (v == null) throw new IllegalStateException("specify a key-strength.");
    return Integer.parseInt(v);
  }

  private int getTagBits(MessageContext msgCtxt) throws Exception {
    String v = _getStringProp(msgCtxt, "tag-bits", defaultKeyStrength);
    if (v == null) return 0;
    return Integer.parseInt(v);
  }

  private int getPbkdf2IterationCount(MessageContext msgCtxt) throws Exception {
    String iterationsString = _getStringProp(msgCtxt, "pbkdf2-iterations", defaultPbkdf2Iterations);
    int iterations = Integer.parseInt(iterationsString);
    if (iterations < minPbkdf2Iterations || iterations > maxPbkdf2Iterations)
      throw new IllegalStateException("the value for PBKDF2 iteration count is out of range.");
    return iterations;
  }

  private int getGcmAadLength(MessageContext msgCtxt) throws Exception {
    String length = _getStringProp(msgCtxt, "gcm-aad-length", defaultGcmAadLength);
    int len = Integer.parseInt(length);
    len = Math.max(Math.min(GCM_MAX_TAG_BYTES, len), GCM_MIN_TAG_BYTES);
    msgCtxt.setVariable(varName("gcmaadlength"), Integer.toString(len));
    return len;
  }

  private String getPadding(MessageContext msgCtxt) throws Exception {
    return _getStringProp(msgCtxt, "padding", defaultCryptoPadding);
  }

  private String getMode(MessageContext msgCtxt) throws Exception {
    return _getStringProp(msgCtxt, "mode", defaultCryptoMode);
  }

  private String getOutputVar(MessageContext msgCtxt) throws Exception {
    return _getStringProp(msgCtxt, "output", varName(defaultOutputVarSuffix));
  }

  private String getPassphrase(MessageContext msgCtxt) throws Exception {
    String passphrase = _getStringProp(msgCtxt, "passphrase", null);
    if (passphrase == null) {
      throw new IllegalStateException("passphrase resolves to null or empty.");
    }
    return passphrase;
  }

  private String getCipher(MessageContext msgCtxt) throws Exception {
    String cipher = (String) this.properties.get("cipher");
    if (cipher != null) cipher = cipher.trim();
    if (cipher == null || cipher.equals("")) {
      return defaultCipherName + "/" + getMode(msgCtxt) + "/" + getPadding(msgCtxt);
    }
    cipher = resolveVariableReferences(cipher, msgCtxt);
    if (cipher == null || cipher.equals("")) {
      throw new IllegalStateException("cipher resolves to null or empty.");
    }
    Matcher m = fullCipherPattern.matcher(cipher);
    if (m.matches()) {
      return cipher;
    }

    m = cipherNamePattern.matcher(cipher);
    if (!m.matches()) {
      throw new IllegalStateException("that cipher name is unsupported.");
    }

    // it is a simple algorithm name; apply mode and padding
    cipher += "/" + getMode(msgCtxt) + "/" + getPadding(msgCtxt);
    m = fullCipherPattern.matcher(cipher);
    if (!m.matches()) {
      throw new IllegalStateException("that cipher is unsupported.");
    }
    return cipher;
  }

  private boolean getUtf8DecodeResult(MessageContext msgCtxt) throws Exception {
    return _getBooleanProperty(msgCtxt, "utf8-decode-result", false);
  }

  private static boolean isGCM(String cipherName) {
    Matcher m = fullGCMCipherPattern.matcher(cipherName);
    return m.matches();
  }

  public byte[] aesEncrypt(
      MessageContext msgCtxt, String cipherName, byte[] key, byte[] iv, byte[] clearText)
      throws Exception {
    Cipher cipher = Cipher.getInstance(cipherName);
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    if (isGCM(cipherName)) {
      byte[] aad = getAad(msgCtxt);
      if (aad == null) {
        throw new IllegalStateException("supply an AAD.");
      }
      emitEncodedOutput(msgCtxt, "aad", aad);
      int tagBits = getTagBits(msgCtxt);
      if (tagBits == 0) tagBits = GCM_AUTH_DEFAULT_TAG_BITS;
      GCMParameterSpec gcmPspec = new GCMParameterSpec(tagBits, iv);
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmPspec);
      cipher.updateAAD(aad);
    } else {
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
    }
    byte[] cryptoText = cipher.doFinal(clearText);
    return cryptoText;
  }

  public byte[] aesDecrypt(
      MessageContext msgCtxt, String cipherName, byte[] key, byte[] iv, byte[] cipherText)
      throws Exception {
    Cipher cipher = Cipher.getInstance(cipherName);
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    if (isGCM(cipherName)) {
      byte[] aad = getAad(msgCtxt);
      if (aad == null) {
        throw new IllegalStateException("supply an AAD.");
      }
      emitEncodedOutput(msgCtxt, "aad", aad);

      byte[] tag = getTag(msgCtxt);
      if (tag != null) {
        emitEncodedOutput(msgCtxt, "tag", tag);
        // upon decryption java expects the tag to be appended to the ciphertext
        byte[] c = new byte[cipherText.length + tag.length];
        System.arraycopy(cipherText, 0, c, 0, cipherText.length);
        System.arraycopy(tag, 0, c, cipherText.length, tag.length);
        cipherText = c;
      }
      GCMParameterSpec gcmPspec = new GCMParameterSpec(GCM_AUTH_DEFAULT_TAG_BITS, iv);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmPspec);
      cipher.updateAAD(aad);
    } else {
      cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
    }
    byte[] clearText = cipher.doFinal(cipherText);
    return clearText;
  }

  @Override
  protected void clearVariables(MessageContext msgCtxt) {
    super.clearVariables(msgCtxt);
    msgCtxt.removeVariable(varName("mode"));
    msgCtxt.removeVariable(varName("padding"));
    msgCtxt.removeVariable(varName("action"));
    msgCtxt.removeVariable(varName("prf"));
  }

  private void setOutput(MessageContext msgCtxt, byte[] key, byte[] iv, byte[] result)
      throws Exception {
    EncodingType outputEncodingWanted = getEncodeResult(msgCtxt);
    String outputVar = getOutputVar(msgCtxt);
    boolean emitGeneratedData = _getBooleanProperty(msgCtxt, "generate-key", false);
    Function<byte[], Object> encoder = null;

    if (outputEncodingWanted == EncodingType.NONE) {
      // Emit the result as a Java byte array.
      // Will be retrievable only by another Java callout.
      msgCtxt.setVariable(varName("output_encoding"), "none");
      encoder = (a) -> a; // nop
    } else if (outputEncodingWanted == EncodingType.BASE64) {
      msgCtxt.setVariable(varName("output_encoding"), "base64");
      encoder = (a) -> Base64.getEncoder().encodeToString(a);
    } else if (outputEncodingWanted == EncodingType.BASE64URL) {
      msgCtxt.setVariable(varName("output_encoding"), "base64url");
      encoder = (a) -> Base64.getUrlEncoder().encodeToString(a);
    } else if (outputEncodingWanted == EncodingType.HEX
        || outputEncodingWanted == EncodingType.BASE16) {
      msgCtxt.setVariable(varName("output_encoding"), "base16");
      encoder = (a) -> Base16.encode(a);
    } else {
      throw new IllegalStateException("unhandled encoding");
    }
    msgCtxt.setVariable(outputVar, encoder.apply(result));
    if (emitGeneratedData) {
      String outputKeyVar = varName("output_key");
      msgCtxt.setVariable(outputKeyVar, encoder.apply(key));
      String outputIvVar = varName("output_iv");
      msgCtxt.setVariable(outputIvVar, encoder.apply(iv));
    }
  }

  protected byte[] generateRandomBytes(int count) {
    byte[] b = new byte[count];
    secureRandom.nextBytes(b);
    return b;
  }

  protected byte[] getSourceBytes(MessageContext msgCtxt) throws Exception {
    Object source1 = msgCtxt.getVariable(getSourceVar());

    if (source1 == null) throw new IllegalStateException("missing source");

    if (source1 instanceof byte[]) {
      return (byte[]) source1;
    }

    if (source1 instanceof String) {
      EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-source");
      return decodeString((String) source1, decodingKind);
    }

    // coerce and hope for the best
    return (source1.toString()).getBytes(StandardCharsets.UTF_8);
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = false;
    try {
      clearVariables(msgCtxt);
      debug = getDebug(msgCtxt);
      byte[] key = getKey(msgCtxt);
      byte[] iv = getIv(msgCtxt);
      boolean generateKey = false;
      byte[] result;

      CryptoAction action = getAction(msgCtxt); // encrypt or decrypt
      msgCtxt.setVariable(varName("action"), action.name().toLowerCase());

      if (key == null) {
        int keyStrengthBits = getKeyStrength(msgCtxt);
        generateKey = _getBooleanProperty(msgCtxt, "generate-key", false);
        if (generateKey) {
          if (action == CryptoAction.DECRYPT) {
            throw new IllegalStateException("senseless to generate a key for decryption");
          }
          System.out.printf("\n** generating key with %d bits\n", keyStrengthBits);

          key = generateRandomBytes(keyStrengthBits / 8);
          if (iv == null) {
            iv = generateRandomBytes(AES_IV_LENGTH / 8);
          }
        } else {
          // derive the key from a passphrase using PBKDF2
          PasswordUtil.PRF prf = getPseudoRandomFunction(msgCtxt);
          String passphrase = getPassphrase(msgCtxt);
          int iterations = getPbkdf2IterationCount(msgCtxt);
          byte[] salt = getSalt(msgCtxt);

          msgCtxt.setVariable(varName("prf"), prf.name().toUpperCase());
          emitEncodedOutput(msgCtxt, "salt", salt);
          msgCtxt.setVariable(varName("pbkdf2_iterations"), String.valueOf(iterations));

          PasswordUtil.KeyAndIv params =
              PasswordUtil.deriveKeyAndIv(
                  passphrase, salt, keyStrengthBits, AES_IV_LENGTH, iterations, prf);
          key = params.getKey();
          if (iv == null) {
            iv = params.getIV();
          }
        }
      }

      String cipherName = getCipher(msgCtxt);
      msgCtxt.setVariable(varName("cipher"), cipherName);

      byte[] source = getSourceBytes(msgCtxt);

      if (iv == null) {
        throw new IllegalStateException("missing IV during decrypt");
      }
      if (debug) {
        emitEncodedOutput(msgCtxt, "key", key);
        emitEncodedOutput(msgCtxt, "iv", iv);
      }

      if (action == CryptoAction.DECRYPT) {
        try {
          result = aesDecrypt(msgCtxt, cipherName, key, iv, source);
        } catch (javax.crypto.BadPaddingException bpe) {
          // a bad key or IV
          bpe.printStackTrace();
          msgCtxt.setVariable(varName("error"), "decryption failed");
          return ExecutionResult.ABORT;
        }
        // maybe decode from UTF-8
        if (getUtf8DecodeResult(msgCtxt)) {
          msgCtxt.setVariable(getOutputVar(msgCtxt), new String(result, StandardCharsets.UTF_8));
        } else {
          setOutput(msgCtxt, null, null, result);
        }
      } else {
        result = aesEncrypt(msgCtxt, cipherName, key, iv, source);
        setOutput(msgCtxt, key, iv, result);
      }
    } catch (Exception e) {
      if (debug) {
        // e.printStackTrace();
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }
}
