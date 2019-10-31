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
import com.google.apigee.util.CalloutUtil;
import com.google.apigee.util.PasswordUtil;
import com.google.apigee.encoding.Base16;
import java.util.Base64;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

@IOIntensive
public class AesCryptoCallout implements Execution {
  private static final int AES_IV_LENGTH = 128;
  private static final int defaultKeyStrength = 128;
  private static final int defaultPbkdf2Iterations = 128001;
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
  private static Pattern fullCipherPattern = Pattern.compile("^(AES)/(CBC|ECB|CFB)/(NoPadding|PKCS5Padding)$", Pattern.CASE_INSENSITIVE);
  private static Pattern cipherNamePattern = Pattern.compile("^(AES)$", Pattern.CASE_INSENSITIVE);
  private static final String commonError = "^(.+?)[:;] (.+)$";
  private static final Pattern commonErrorPattern = Pattern.compile(commonError);

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
  enum EncodingType { NONE, BASE64, HEX };

  private static String varName(String s) {return varprefix + s;}

  private String getSourceVar()  {
    String source = this.properties.get("source");
    if (source == null || source.equals("")) {
      // by default, get the content of the message (either request or response)
      return "message.content";
    }
    return source;
  }

  private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
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

  private String getOutputVar(MessageContext msgCtxt) throws Exception {
    String output = this.properties.get("output");
    if (output == null) {
      return varName(defaultOutputVarSuffix);
    }
    output = output.trim();
    if (output.equals("")) {
      return varName(defaultOutputVarSuffix);
    }
    output = resolvePropertyValue(output, msgCtxt);
    if (output == null || output.equals("")) {
      throw new IllegalStateException("output resolves to null or empty.");
    }
    return output;
  }

  private byte[] getIv(MessageContext msgCtxt) throws Exception {
    return _getByteArrayProperty(msgCtxt, "iv");
  }

  private byte[] getKey(MessageContext msgCtxt) throws Exception {
    return _getByteArrayProperty(msgCtxt, "key");
  }

  private byte[] getSalt(MessageContext msgCtxt) throws Exception {
    byte[] result = _getByteArrayProperty(msgCtxt, "salt");
    return (result==null)? defaultSalt : result;
  }

  private EncodingType _getEncodingTypeProperty(MessageContext msgCtxt, String propName) throws Exception {
    String decode = this.properties.get(propName);
    if (decode == null) {
      return EncodingType.NONE;
    }
    decode = decode.trim();
    if(decode.equals("")) {
      return EncodingType.NONE;
    }
    decode = resolvePropertyValue(decode, msgCtxt);
    if (decode == null || decode.equals("")) {
      return EncodingType.NONE;
    }
    return EncodingType.valueOf(decode.toUpperCase());
  }

  private byte[] _getByteArrayProperty(MessageContext msgCtxt, String propName) throws Exception {
    String key = this.properties.get(propName);
    if (key == null) {
      return null;
    }
    key = key.trim();
    if (key.equals("")) {
      return null;
    }
    key = resolvePropertyValue(key, msgCtxt);
    if (key == null || key.equals("")) {
      throw new IllegalStateException(propName + " resolves to null or empty.");
    }
    EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-" + propName);
    return decodeString(key, decodingKind);
  }

  private byte[] decodeString(String s, EncodingType decodingKind) throws Exception {
    if (decodingKind == EncodingType.HEX) {
      return Base16.decode(s);
    }
    if (decodingKind == EncodingType.BASE64) {
      return Base64.getDecoder().decode(s);
    }
    return s.getBytes(StandardCharsets.UTF_8);
  }

  private CryptoAction getAction(MessageContext msgCtxt) throws Exception {
    String action = this.properties.get("action");
    if (action == null) {
      throw new IllegalStateException("specify an action.");
    }
    action = action.trim();
    if (action.equals("")) {
      throw new IllegalStateException("specify an action.");
    }
    action = resolvePropertyValue(action, msgCtxt);
    return CryptoAction.valueOf(action.toUpperCase());
  }

  private int getKeyStrength(MessageContext msgCtxt) throws Exception {
    String bits = this.properties.get("key-strength");
    if (bits == null) {
      return defaultKeyStrength;
    }
    bits = bits.trim();
    if (bits.equals("")) {
      return defaultKeyStrength;
    }
    bits = resolvePropertyValue(bits, msgCtxt);
    return Integer.parseInt(bits);
  }

  private int getPbkdf2IterationCount(MessageContext msgCtxt) throws Exception {
    String iterations = this.properties.get("pbkdf2-iterations");
    if (iterations == null) {
      return defaultPbkdf2Iterations;
    }
    iterations = iterations.trim();
    if (iterations.equals("")) {
      return defaultPbkdf2Iterations;
    }
    iterations = resolvePropertyValue(iterations, msgCtxt);
    return Integer.parseInt(iterations);
  }

  private String getPassphrase(MessageContext msgCtxt) throws Exception {
    String passphrase = this.properties.get("passphrase");
    if (passphrase == null) {
      throw new IllegalStateException("passphrase resolves to null or empty.");
    }
    passphrase = passphrase.trim();
    if (passphrase.equals("")) {
      throw new IllegalStateException("passphrase resolves to null or empty.");
    }
    passphrase = resolvePropertyValue(passphrase, msgCtxt);
    if (passphrase == null || passphrase.equals("")) {
      throw new IllegalStateException("passphrase resolves to null or empty.");
    }
    return passphrase;
  }

  private String getMode(MessageContext msgCtxt) throws Exception {
    String mode = this.properties.get("mode");
    if (mode != null) mode = mode.trim();
    if (mode == null || mode.equals("")) {
      return defaultCryptoMode;
    }
    mode = resolvePropertyValue(mode, msgCtxt);
    if (mode == null || mode.equals("")) {
      throw new IllegalStateException("mode resolves to null or empty.");
    }
    return mode;
  }

  private String getPadding(MessageContext msgCtxt) throws Exception {
    String padding = this.properties.get("padding");
    if (padding != null) padding = padding.trim();
    if (padding == null || padding.equals("")) {
      return defaultCryptoPadding;
    }
    padding = resolvePropertyValue(padding, msgCtxt);
    if (padding == null || padding.equals("")) {
      throw new IllegalStateException("padding resolves to null or empty.");
    }
    return padding;
  }

  private String getCipher(MessageContext msgCtxt) throws Exception {
    String cipher = (String) this.properties.get("cipher");
    if (cipher != null) cipher = cipher.trim();
    if (cipher == null || cipher.equals("")) {
      return defaultCipherName + "/" + getMode(msgCtxt) + "/" + getPadding(msgCtxt);
    }
    cipher = resolvePropertyValue(cipher, msgCtxt);
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
    if (flag == null) {
      return defaultValue;
    }
    flag = flag.trim();
    if (flag.equals("")) {
      return defaultValue;
    }
    flag = resolvePropertyValue(flag, msgCtxt);
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    return flag.equalsIgnoreCase(TRUE);
  }

  private EncodingType getEncodeResult(MessageContext msgCtxt) throws Exception {
    String encode = this.properties.get("encode-result");
    if (encode != null) encode = encode.trim();
    if (encode == null || encode.equals("")) {
      return EncodingType.NONE;
    }
    encode = resolvePropertyValue(encode, msgCtxt);
    if (encode == null || encode.equals("")) {
      return EncodingType.NONE;
    }
    return EncodingType.valueOf(encode.toUpperCase());
  }

  private boolean getUtf8DecodeResult(MessageContext msgCtxt) throws Exception {
    return _getBooleanProperty(msgCtxt, "utf8-decode-result", false);
  }

  public static byte[] aesEncrypt(String cipherName, byte[] key, byte[] iv, byte[] clearText) throws Exception {
    Cipher cipher = Cipher.getInstance(cipherName);
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    byte[] cryptoText = cipher.doFinal(clearText);
    return cryptoText;
  }

  public static byte[] aesDecrypt(String cipherName, byte[] key, byte[] iv, byte[] cipherText) throws Exception {
    Cipher cipher = Cipher.getInstance(cipherName);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    byte[] clearText = cipher.doFinal(cipherText);
    return clearText;
  }

  private void clearVariables(MessageContext msgCtxt) {
    msgCtxt.removeVariable(varName("error"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
    msgCtxt.removeVariable(varName("mode"));
    msgCtxt.removeVariable(varName("padding"));
    msgCtxt.removeVariable(varName("action"));
  }

  private void emitEncodedOutput(MessageContext msgCtxt, String name, byte[] data) {
    String encoded = Base16.encode(data);
    msgCtxt.setVariable(varName(name + "_hex"), encoded);
    encoded = Base64.getUrlEncoder().encodeToString(data);
    msgCtxt.setVariable(varName(name + "_b64"), encoded);
  }

  private void setOutput(MessageContext msgCtxt, byte[] result) throws Exception {
    EncodingType outputEncodingWanted = getEncodeResult(msgCtxt);
    String outputVar = getOutputVar(msgCtxt);
    if (outputEncodingWanted == EncodingType.BASE64) {
      msgCtxt.setVariable(varName("output_encoding"), "base64");
      msgCtxt.setVariable(outputVar, Base64.getUrlEncoder().encodeToString(result));
    }
    else if (outputEncodingWanted == EncodingType.HEX) {
      msgCtxt.setVariable(varName("output_encoding"), "hex");
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
        byte salt[] = getSalt(msgCtxt);

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

      if (source1 instanceof byte[]) {
        source = (byte[])source1;
      }
      else if (source1 instanceof String) {
        EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-source");
        source = decodeString((String)source1, decodingKind);
      }
      else {
        // coerce and hope for the best?
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
          result = aesDecrypt(cipherName, key, iv, source);
        }
        catch (javax.crypto.BadPaddingException bpe) {
          // a bad key or IV
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
        result = aesEncrypt(cipherName, key, iv, source);
        setOutput(msgCtxt, result);
      }
    }
    catch (Exception e){
      if (debug) {
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }
}
