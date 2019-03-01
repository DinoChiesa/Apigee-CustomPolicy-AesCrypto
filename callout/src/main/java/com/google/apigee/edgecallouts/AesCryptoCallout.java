// AesCryptoCallout.java
//
// This is the main callout class for the AES Crypto custom policy for Apigee Edge.
// For full details see the Readme accompanying this source file.
//
// Copyright (c) 2016 Apigee Corp, 2017 Google LLC.
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

import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.lang.text.StrSubstitutor;

import com.google.apigee.edgecallouts.util.CalloutUtil;
import com.google.apigee.edgecallouts.util.PasswordUtil;
import com.google.apigee.edgecallouts.util.VariableRefResolver;

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

    // private static Pattern fullCipherPattern = Pattern.compile("^(DES|DESede|AES)/(CBC|EBC)/(NoPadding|PKCS5Padding)$", Pattern.CASE_INSENSITIVE);
    // private static Pattern cipherNamePattern = Pattern.compile("^(DES|DESede|AES)$", Pattern.CASE_INSENSITIVE);
    private static Pattern fullCipherPattern = Pattern.compile("^(AES)/(CBC|ECB|CFB)/(NoPadding|PKCS5Padding)$", Pattern.CASE_INSENSITIVE);
    private static Pattern cipherNamePattern = Pattern.compile("^(AES)$", Pattern.CASE_INSENSITIVE);
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

    /*
     * returns a variable name that contains the source, the data to
     * be encrypted or decrypted.
     *
     ******/
    private String getSourceVar()  {
        String source = this.properties.get("source");
        if (source == null || source.equals("")) {
            // by default, get the content of the message (either request or response)
            return "message.content";
        }
        return source;
    }

    private byte[] decodeSource(VariableRefResolver resolver,String source) throws Exception {
        EncodingType decodingKind = _getEncodingTypeProperty(resolver, "decode-source");
        return decodeString(source, decodingKind);
    }

    private String getOutputVar(VariableRefResolver resolver) throws Exception {
        String output = this.properties.get("output");
        if (output == null || output.equals("")) {
            return varName(defaultOutputVarSuffix);
        }
        output = resolver.resolve(output);
        if (output == null || output.equals("")) {
            throw new IllegalStateException("output resolves to null or empty.");
        }
        return output;
    }

    private byte[] getIv(VariableRefResolver resolver) throws Exception {
        return _getByteArrayProperty(resolver, "iv");
    }

    private byte[] getKey(VariableRefResolver resolver) throws Exception {
        return _getByteArrayProperty(resolver, "key");
    }

    private byte[] getSalt(VariableRefResolver resolver) throws Exception {
        byte[] result = _getByteArrayProperty(resolver, "salt");
        return (result==null)? defaultSalt : result;
    }

    private EncodingType _getEncodingTypeProperty(VariableRefResolver resolver, String propName) throws Exception {
        String decode = this.properties.get(propName);
        if (decode == null || decode.equals("")) {
            return EncodingType.NONE;
        }
        decode = resolver.resolve(decode);
        if (decode == null || decode.equals("")) {
            return EncodingType.NONE;
        }
        return EncodingType.valueOf(decode.toUpperCase());
    }

    private byte[] _getByteArrayProperty(VariableRefResolver resolver, String propName) throws Exception {
        String key = this.properties.get(propName);
        if (key == null || key.equals("")) {
            return null;
        }
        key = resolver.resolve(key);
        if (key == null || key.equals("")) {
            throw new IllegalStateException(propName + " resolves to null or empty.");
        }
        EncodingType decodingKind = _getEncodingTypeProperty(resolver, "decode-" + propName);
        return decodeString(key, decodingKind);
    }

    private byte[] decodeString(String s, EncodingType decodingKind) throws Exception {
        if (decodingKind == EncodingType.HEX) {
            return Hex.decodeHex(s.toCharArray());
        }
        if (decodingKind == EncodingType.BASE64) {
            return Base64.decodeBase64(s);
        }
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private CryptoAction getAction(VariableRefResolver resolver) throws Exception {
        String action = this.properties.get("action");
        if (action == null || action.equals("")) {
            throw new IllegalStateException("specify an action.");
        }
        action = resolver.resolve(action);
        return CryptoAction.valueOf(action.toUpperCase());
    }

    private int getKeyStrength(VariableRefResolver resolver) throws Exception {
        String bits = this.properties.get("key-strength");
        if (bits == null || bits.equals("")) {
            return defaultKeyStrength;
        }
        bits = resolver.resolve(bits);
        return NumberUtils.toInt(bits);
    }

    private int getPbkdf2IterationCount(VariableRefResolver resolver) throws Exception {
        String iterations = this.properties.get("pbkdf2-iterations");
        if (iterations == null || iterations.equals("")) {
            return defaultPbkdf2Iterations;
        }
        iterations = resolver.resolve(iterations);
        return NumberUtils.toInt(iterations);
    }

    private String getPassphrase(VariableRefResolver resolver) throws Exception {
        String passphrase = this.properties.get("passphrase");
        if (passphrase == null || passphrase.equals("")) {
            throw new IllegalStateException("passphrase resolves to null or empty.");
        }
        else {
            passphrase = resolver.resolve(passphrase);
        }
        if (passphrase == null || passphrase.equals("")) {
            throw new IllegalStateException("passphrase resolves to null or empty.");
        }
        return passphrase;
    }

    private String getMode(VariableRefResolver resolver) throws Exception {
        String mode = this.properties.get("mode");
        if (mode == null || mode.equals("")) {
            return defaultCryptoMode;
        }
        mode = resolver.resolve(mode);
        if (mode == null || mode.equals("")) {
            throw new IllegalStateException("mode resolves to null or empty.");
        }
        return mode;
    }

    private String getPadding(VariableRefResolver resolver) throws Exception {
        String padding = this.properties.get("padding");
        if (padding == null || padding.equals("")) {
            return defaultCryptoPadding;
        }
        padding = resolver.resolve(padding);
        if (padding == null || padding.equals("")) {
            throw new IllegalStateException("padding resolves to null or empty.");
        }
        return padding;
    }

    private String getCipher(VariableRefResolver resolver) throws Exception {
        String cipher = (String) this.properties.get("cipher");
        if (cipher == null || cipher.equals("")) {
            return defaultCipherName + "/" + getMode(resolver) + "/" + getPadding(resolver);
        }
        cipher = resolver.resolve(cipher);
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
        cipher += "/" + getMode(resolver) + "/" + getPadding(resolver);
        m = fullCipherPattern.matcher(cipher);
        if (!m.matches()) {
            throw new IllegalStateException("that cipher is unsupported.");
        }
        return cipher;
    }

    private boolean getDebug(VariableRefResolver resolver) throws Exception {
        return _getBooleanProperty(resolver, "debug", false);
    }
    private boolean _getBooleanProperty(VariableRefResolver resolver, String propName, boolean defaultValue) throws Exception {
        String flag = this.properties.get(propName);
        if (flag == null || flag.equals("")) {
            return defaultValue;
        }
        flag = resolver.resolve(flag);
        if (flag == null || flag.equals("")) {
            return defaultValue;
        }
        return flag.equalsIgnoreCase(TRUE);
    }

    private EncodingType getEncodeResult(VariableRefResolver resolver) throws Exception {
        String encode = this.properties.get("encode-result");
        if (encode == null || encode.equals("")) {
            return EncodingType.NONE;
        }
        encode = resolver.resolve(encode);
        if (encode == null || encode.equals("")) {
            return EncodingType.NONE;
        }
        return EncodingType.valueOf(encode.toUpperCase());
    }

    private boolean getUtf8DecodeResult(VariableRefResolver resolver) throws Exception {
        return _getBooleanProperty(resolver, "utf8-decode-result", false);
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
        String encoded = Hex.encodeHexString(data);
        msgCtxt.setVariable(varName(name + "_hex"), encoded);
        //encoded = Base64.encodeBase64String(data);
        encoded = Base64.encodeBase64URLSafeString(data);
        msgCtxt.setVariable(varName(name + "_b64"), encoded);
    }

    private void setOutput(VariableRefResolver resolver, MessageContext msgCtxt, byte[] result) throws Exception {
        EncodingType outputEncodingWanted = getEncodeResult(resolver);
        String outputVar = getOutputVar(resolver);
        if (outputEncodingWanted == EncodingType.BASE64) {
            msgCtxt.setVariable(varName("output_encoding"), "base64");
            msgCtxt.setVariable(outputVar, Base64.encodeBase64URLSafeString(result));
        }
        else if (outputEncodingWanted == EncodingType.HEX) {
            msgCtxt.setVariable(varName("output_encoding"), "hex");
            msgCtxt.setVariable(outputVar, Hex.encodeHexString(result));
        }
        else {
            // emit the result as a Java byte array
            msgCtxt.setVariable(varName("output_encoding"), "none");
            msgCtxt.setVariable(outputVar, result);
        }
    }

    public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
        boolean debug = false;
        try {
            VariableRefResolver resolver = new VariableRefResolver(s -> ((String) msgCtxt.getVariable(s)));
            clearVariables(msgCtxt);
            debug = getDebug(resolver);
            byte[] key = getKey(resolver);
            byte[] iv = getIv(resolver);
            byte[] result;
            PasswordUtil.KeyAndIv params = null;

            if (key == null) {
                // derive the key from a passphrase using PBKDF2
                String passphrase = getPassphrase(resolver);
                int keyStrengthBits = getKeyStrength(resolver);
                int iterations = getPbkdf2IterationCount(resolver);
                byte salt[] = getSalt(resolver);

                emitEncodedOutput(msgCtxt, "salt", salt);
                msgCtxt.setVariable(varName("pbkdf2_iterations"), String.valueOf(iterations));

                params = PasswordUtil.deriveKeyAndIv(passphrase, salt, keyStrengthBits, AES_IV_LENGTH, iterations);
                key = params.getKey();
                if (iv==null) { iv = params.getIV(); }
            }

            String cipherName = getCipher(resolver);
            msgCtxt.setVariable(varName("cipher"), cipherName);

            CryptoAction action = getAction(resolver); // encrypt or decrypt
            msgCtxt.setVariable(varName("action"), action.name().toLowerCase());
            Object source1 = msgCtxt.getVariable(getSourceVar());
            byte[] source;

            if (source1 instanceof byte[]) {
                source = (byte[])source1;
            }
            else if (source1 instanceof String) {
                source = decodeSource(resolver, (String)source1);
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
                if (getUtf8DecodeResult(resolver)) {
                    msgCtxt.setVariable(getOutputVar(resolver), new String(result, StandardCharsets.UTF_8));
                }
                else {
                    setOutput(resolver, msgCtxt, result);
                }
            }
            else {
                result = aesEncrypt(cipherName, key, iv, source);
                setOutput(resolver, msgCtxt, result);
            }
        }
        catch (Exception e){
            if (debug) {
                System.out.println(ExceptionUtils.getStackTrace(e));
            }
            String error = e.toString();
            msgCtxt.setVariable(varName("exception"), error);
            int ch = error.lastIndexOf(':');
            if (ch >= 0) {
                msgCtxt.setVariable(varName("error"), error.substring(ch+2).trim());
            }
            else {
                msgCtxt.setVariable(varName("error"), error);
            }
            msgCtxt.setVariable(varName("stacktrace"), ExceptionUtils.getStackTrace(e));
            return ExecutionResult.ABORT;
        }
        return ExecutionResult.SUCCESS;
    }
}
