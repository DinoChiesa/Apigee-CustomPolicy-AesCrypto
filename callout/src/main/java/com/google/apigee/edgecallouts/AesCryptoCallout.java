// AesCryptoCallout.java
//
// This is the main callout class for the AES Crypto custom policy for Apigee Edge.
// For full details see the Readme accompanying this source file.
//
// Copyright (c) 2016 Apigee Corp, 2017-2019 Google LLC.
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
// Saturday, 21 May 2016, 08:59
//

package com.google.apigee.edgecallouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.encoding.Base16;
import com.google.apigee.util.CalloutUtil;
import com.google.apigee.util.PasswordUtil;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.IntSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

@IOIntensive
public class AesCryptoCallout implements Execution {
  private static final int AES_IV_LENGTH = 128;
  private static final int GCM_AUTH_DEFAULT_TAG_BITS = 128;
  private static final String defaultKeyStrength = "128";
  private static final String defaultPbkdf2Iterations = "128001";
  private static final String defaultCipherName = "AES";
  private static final String defaultCryptoMode = "CBC";
  private static final String defaultCryptoPadding = "PKCS5PADDING";
  private static final String varprefix = "crypto_";
  private static final String defaultOutputVarSuffix = "output";
  private static final String TRUE = "true";
  private static final byte[] defaultSalt = "Apigee-IloveAPIs".getBytes(StandardCharsets.UTF_8);
  private static final SecretKeyFactory secretKeyFactory;

  private static final String variableReferencePatternString = "(.*?)\\{([^\\{\\} :][^\\{\\} ]*?)\\}(.*?)";
  private static final Pattern variableReferencePattern =
    Pattern.compile(variableReferencePatternString);
  private static Pattern fullCipherPattern = Pattern.compile("^(AES)/(CBC|ECB|CFB|GCM)/(NoPadding|PKCS5Padding)$", Pattern.CASE_INSENSITIVE);
  private static Pattern cipherNamePattern = Pattern.compile("^(AES)$", Pattern.CASE_INSENSITIVE);

  private static Pattern fullGCMCipherPattern = Pattern.compile("^(AES)/GCM/(NoPadding|PKCS5Padding)$", Pattern.CASE_INSENSITIVE);

  private static final String commonError = "^(.+?)[:;] (.+)$";
  private static final Pattern commonErrorPattern = Pattern.compile(commonError);
  private static final String defaultGcmAadLength = "16";
  //private static final int GCM_DEFAULT_TAG_BYTES = 16;
  private static final int GCM_MIN_TAG_BYTES = 0;
  private static final int GCM_MAX_TAG_BYTES = 2048;

  private final Map<String,String> properties;

  static {
    try{
      secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    }
    catch(final Exception ex){
      throw new RuntimeException("Failed to create secretKeyFactory instance in static block.", ex);
    }
  }

  public AesCryptoCallout(Map properties) {
    this.properties = CalloutUtil.genericizeMap(properties);
  }

  enum CryptoAction { DECRYPT, ENCRYPT };
  enum EncodingType { NONE, BASE64, BASE64URL, BASE16, HEX };

  private static String varName(String s) {return varprefix + s;}

  private String getSourceVar()  {
    String source = this.properties.get("source");
    if (source == null || source.equals("")) {
      // by default, get the content of the message (either request or response)
      return "message.content";
    }
    return source;
  }

  private String resolveVariableReferences(String spec, MessageContext msgCtxt) {
    Matcher matcher = variableReferencePattern.matcher(spec);
    StringBuffer sb = new StringBuffer();
    while (matcher.find()) {
      matcher.appendReplacement(sb, "");
      sb.append(matcher.group(1));
      String ref = matcher.group(2);
      String[] parts = ref.split(":",2);
      Object v = msgCtxt.getVariable(parts[0]);
      if (v != null) {
        sb.append((String) v);
      }
      else if (parts.length>1){
        sb.append(parts[1]);
      }
      sb.append(matcher.group(3));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  private byte[] _getByteArrayProperty(MessageContext msgCtxt, String propName) throws Exception {
    String key = this.properties.get(propName);
    if (key != null) key = key.trim();
    if (key == null || key.equals("")) {
      return null;
    }
    key = resolveVariableReferences(key, msgCtxt);
    if (key == null || key.equals("")) {
      throw new IllegalStateException(propName + " resolves to null or empty.");
    }
    EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-" + propName);
    byte[] a = decodeString(key, decodingKind);
    return a;
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
    return (result==null)? defaultSalt : result;
  }

  private String _getStringProp(MessageContext msgCtxt, String name, String defaultValue) throws Exception {
    String value = this.properties.get(name);
    if (value != null) value = value.trim();
    if (value == null || value.equals("")) {
      return defaultValue;
    }
    value = resolveVariableReferences(value, msgCtxt);
    if (value == null || value.equals("")) {
      throw new IllegalStateException(name + " resolves to null or empty.");
    }
    return value;
  }

  private EncodingType _getEncodingTypeProperty(MessageContext msgCtxt, String propName) throws Exception {
    return EncodingType
      .valueOf(_getStringProp(msgCtxt, propName, "NONE")
               .toUpperCase());
  }

  private EncodingType getEncodeResult(MessageContext msgCtxt) throws Exception {
    return _getEncodingTypeProperty( msgCtxt, "encode-result");
  }

  private byte[] decodeString(String s, EncodingType decodingKind) throws Exception {
    if (decodingKind == EncodingType.HEX || decodingKind == EncodingType.BASE16) {
      return Base16.decode(s);
    }
    if (decodingKind == EncodingType.BASE64) {
      return Base64.getDecoder().decode(s);
    }
    if (decodingKind == EncodingType.BASE64URL) {
      return Base64.getUrlDecoder().decode(s);
    }
    return s.getBytes(StandardCharsets.UTF_8);
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

  private int getKeyStrength(MessageContext msgCtxt) throws Exception {
    String v = _getStringProp(msgCtxt, "key-strength", defaultKeyStrength);
    if (v==null)
      throw new IllegalStateException("specify a key-strength.");
    return Integer.parseInt(v);
  }

  private int getTagBits(MessageContext msgCtxt) throws Exception {
    String v = _getStringProp(msgCtxt, "tag-bits", defaultKeyStrength);
    if (v==null)
      return 0;
    return Integer.parseInt(v);
  }

  private int getPbkdf2IterationCount(MessageContext msgCtxt) throws Exception {
    String iterations = _getStringProp(msgCtxt, "pbkdf2-iterations", defaultPbkdf2Iterations);
    return Integer.parseInt(iterations);
  }

  private int getGcmAadLength(MessageContext msgCtxt) throws Exception {
    String length = _getStringProp(msgCtxt, "gcm-aad-length", defaultGcmAadLength);
    int len = Integer.parseInt(length);
    len =  Math.max(Math.min(GCM_MAX_TAG_BYTES, len),GCM_MIN_TAG_BYTES);
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

  private boolean getDebug(MessageContext msgCtxt) throws Exception {
    return _getBooleanProperty(msgCtxt, "debug", false);
  }

  private boolean _getBooleanProperty(MessageContext msgCtxt, String propName, boolean defaultValue) throws Exception {
    String flag = this.properties.get(propName);
    if (flag != null) flag = flag.trim();
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    flag = resolveVariableReferences(flag, msgCtxt);
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    return flag.equalsIgnoreCase(TRUE);
  }

  private boolean getUtf8DecodeResult(MessageContext msgCtxt) throws Exception {
    return _getBooleanProperty(msgCtxt, "utf8-decode-result", false);
  }

  private static boolean isGCM(String cipherName) {
    Matcher m = fullGCMCipherPattern.matcher(cipherName);
    return m.matches();
  }

  public byte[] aesEncrypt(MessageContext msgCtxt, String cipherName, byte[] key, byte[] iv, byte[] clearText) throws Exception {
    Cipher cipher = Cipher.getInstance(cipherName);
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    if (isGCM(cipherName)) {
      byte[] aad = getAad(msgCtxt);
      if (aad == null) {
        throw new IllegalStateException("supply an AAD.");
      }
      emitEncodedOutput(msgCtxt, "aad", aad);
      int tagBits = getTagBits(msgCtxt);
      if (tagBits==0) tagBits = GCM_AUTH_DEFAULT_TAG_BITS;
      GCMParameterSpec gcmPspec = new GCMParameterSpec(tagBits, iv);
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmPspec);
      cipher.updateAAD(aad);
    }
    else {
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
    }
    byte[] cryptoText = cipher.doFinal(clearText);
    return cryptoText;
  }

  public byte[] aesDecrypt(MessageContext msgCtxt, String cipherName, byte[] key, byte[] iv, byte[] cipherText) throws Exception {
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
    }
    else {
      cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
    }
    byte[] clearText = cipher.doFinal(cipherText);
    return clearText;
  }

  private static void clearVariables(MessageContext msgCtxt) {
    msgCtxt.removeVariable(varName("error"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
    msgCtxt.removeVariable(varName("mode"));
    msgCtxt.removeVariable(varName("padding"));
    msgCtxt.removeVariable(varName("action"));
  }

  private static void emitEncodedOutput(MessageContext msgCtxt, String name, byte[] data) {
    String encoded = Base16.encode(data);
    msgCtxt.setVariable(varName(name + "_b16"), encoded);
    encoded = Base64.getUrlEncoder().encodeToString(data);
    msgCtxt.setVariable(varName(name + "_b64url"), encoded);
    encoded = Base64.getEncoder().encodeToString(data);
    msgCtxt.setVariable(varName(name + "_b64"), encoded);
  }

  private void setOutput(MessageContext msgCtxt, byte[] result) throws Exception {
    EncodingType outputEncodingWanted = getEncodeResult(msgCtxt);
    String outputVar = getOutputVar(msgCtxt);
    if (outputEncodingWanted == EncodingType.BASE64) {
      msgCtxt.setVariable(varName("output_encoding"), "base64");
      msgCtxt.setVariable(outputVar, Base64.getEncoder().encodeToString(result));
    }
    else if (outputEncodingWanted == EncodingType.BASE64URL) {
      msgCtxt.setVariable(varName("output_encoding"), "base64url");
      msgCtxt.setVariable(outputVar, Base64.getUrlEncoder().encodeToString(result));
    }
    else if (outputEncodingWanted == EncodingType.HEX || outputEncodingWanted == EncodingType.BASE16) {
      msgCtxt.setVariable(varName("output_encoding"), "base16");
      msgCtxt.setVariable(outputVar, Base16.encode(result));
    }
    else {
      // emit the result as a Java byte array
      msgCtxt.setVariable(varName("output_encoding"), "none");
      msgCtxt.setVariable(outputVar, result);
    }
  }

  private static String getStackTraceAsString(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    return sw.toString();
  }

  private void setExceptionVariables(Exception exc1, MessageContext msgCtxt) {
    String error = exc1.toString().replaceAll("\n"," ");
    msgCtxt.setVariable(varName("exception"), error);
    Matcher matcher = commonErrorPattern.matcher(error);
    if (matcher.matches()) {
      msgCtxt.setVariable(varName("error"), matcher.group(2));
    }
    else {
      msgCtxt.setVariable(varName("error"), error);
    }
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = false;
    try {
      clearVariables(msgCtxt);
      debug = getDebug(msgCtxt);
      byte[] key = getKey(msgCtxt);
      byte[] iv = getIv(msgCtxt);
      byte[] result;
      PasswordUtil.KeyAndIv params = null;

      if (key == null) {
        // derive the key from a passphrase using PBKDF2
        String passphrase = getPassphrase(msgCtxt);
        int keyStrengthBits = getKeyStrength(msgCtxt);
        int iterations = getPbkdf2IterationCount(msgCtxt);
        byte[] salt = getSalt(msgCtxt);

        emitEncodedOutput(msgCtxt, "salt", salt);
        msgCtxt.setVariable(varName("pbkdf2_iterations"), String.valueOf(iterations));

        params = PasswordUtil.deriveKeyAndIv(passphrase, salt, keyStrengthBits, AES_IV_LENGTH, iterations);
        key = params.getKey();
        if (iv==null) { iv = params.getIV(); }
      }

      String cipherName = getCipher(msgCtxt);
      msgCtxt.setVariable(varName("cipher"), cipherName);

      CryptoAction action = getAction(msgCtxt); // encrypt or decrypt
      msgCtxt.setVariable(varName("action"), action.name().toLowerCase());
      Object source1 = msgCtxt.getVariable(getSourceVar());
      byte[] source;

      if (source1 == null)
        throw new IllegalStateException("missing source");

      if (source1 instanceof byte[]) {
        source = (byte[])source1;
      }
      else if (source1 instanceof String) {
        EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-source");
        source = decodeString((String)source1, decodingKind);
      }
      else {
        // coerce and hope for the best
        source = (source1.toString()).getBytes(StandardCharsets.UTF_8);
      }

      if (iv == null) {
        throw new IllegalStateException("missing IV during decrypt");
      }
      if (debug) {
        emitEncodedOutput(msgCtxt,"key",key);
        emitEncodedOutput(msgCtxt,"iv",iv);
      }

      if (action == CryptoAction.DECRYPT) {
        try {
          result = aesDecrypt(msgCtxt, cipherName, key, iv, source);
        }
        catch (javax.crypto.BadPaddingException bpe) {
          // a bad key or IV
          bpe.printStackTrace();
          msgCtxt.setVariable(varName("error"), "decryption failed");
          return ExecutionResult.ABORT;
        }
        // maybe decode from UTF-8
        if (getUtf8DecodeResult(msgCtxt)) {
          msgCtxt.setVariable(getOutputVar(msgCtxt), new String(result, StandardCharsets.UTF_8));
        }
        else {
          setOutput(msgCtxt, result);
        }
      }
      else {
        result = aesEncrypt(msgCtxt, cipherName, key, iv, source);
        setOutput(msgCtxt, result);
      }
    }
    catch (Exception e){
      if (debug) {
        //e.printStackTrace();
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }
}
