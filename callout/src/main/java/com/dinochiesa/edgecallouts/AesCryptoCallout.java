// AesCryptoCallout.java
//
// This is the main callout class for the AES Crypto custom policy for Apigee Edge.
// For full details see the Readme accompanying this source file.
//
// Copyright (c) 2016 Apigee Corp
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

package com.dinochiesa.edgecallouts;

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

import com.dinochiesa.edgecallouts.util.CalloutUtil;
import com.dinochiesa.edgecallouts.util.PasswordUtil;

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
    private static Pattern fullCipherPattern = Pattern.compile("^(AES)/(CBC|EBC|CFB)/(NoPadding|PKCS5Padding)$", Pattern.CASE_INSENSITIVE);
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
    
    private byte[] decodeSource(MessageContext msgCtxt, String source) throws Exception {
        EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-source");
        return decodeString(source, decodingKind);
    }

    private String getOutputVar(MessageContext msgCtxt) throws Exception {
        String output = this.properties.get("output");
        if (output == null || output.equals("")) {
            return varName(defaultOutputVarSuffix);
        }
        output = CalloutUtil.resolveVariableFromContext(output, msgCtxt);
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
        if (decode == null || decode.equals("")) {
            return EncodingType.NONE;
        }
        decode = CalloutUtil.resolveVariableFromContext(decode, msgCtxt);
        if (decode == null || decode.equals("")) {
            return EncodingType.NONE;
        }
        return EncodingType.valueOf(decode.toUpperCase());
    }
    
    private byte[] _getByteArrayProperty(MessageContext msgCtxt, String propName) throws Exception {
        String key = this.properties.get(propName);
        if (key == null || key.equals("")) {
            return null;
        }
        key = CalloutUtil.resolveVariableFromContext(key, msgCtxt);
        if (key == null || key.equals("")) {
            throw new IllegalStateException(propName + " resolves to null or empty.");
        }
        EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-" + propName);
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
    
    private CryptoAction getAction(MessageContext msgCtxt) throws Exception {
        String action = this.properties.get("action");
        if (action == null || action.equals("")) {
            throw new IllegalStateException("specify an action.");
        }
        action = CalloutUtil.resolveVariableFromContext(action, msgCtxt);
        return CryptoAction.valueOf(action.toUpperCase());
    }

    private int getKeyStrength(MessageContext msgCtxt) throws Exception {
        String bits = this.properties.get("key-strength");
        if (bits == null || bits.equals("")) {
            return defaultKeyStrength;
        }
        bits = CalloutUtil.resolveVariableFromContext(bits, msgCtxt);
        return NumberUtils.toInt(bits);
    }

    private int getPbkdf2IterationCount(MessageContext msgCtxt) throws Exception {
        String iterations = this.properties.get("pbkdf2-iterations");
        if (iterations == null || iterations.equals("")) {
            return defaultPbkdf2Iterations;
        }
        iterations = CalloutUtil.resolveVariableFromContext(iterations, msgCtxt);
        return NumberUtils.toInt(iterations);
    }

    private String getPassphrase(MessageContext msgCtxt) throws Exception {
        String passphrase = this.properties.get("passphrase");
        if (passphrase == null || passphrase.equals("")) {
            // by default, get the client_secret.
            // This string is often just 16 chars long.  MAY not have enough entropy for DESede !
            passphrase = msgCtxt.getVariable("client_secret");
        }
        else {
            passphrase = CalloutUtil.resolveVariableFromContext(passphrase, msgCtxt);
        }
        if (passphrase == null || passphrase.equals("")) {
            throw new IllegalStateException("passphrase resolves to null or empty.");
        }
        return passphrase;
    }

    private String getMode(MessageContext msgCtxt) throws Exception {
        String mode = this.properties.get("mode");
        if (mode == null || mode.equals("")) {
            return defaultCryptoMode;
        }
        mode = CalloutUtil.resolveVariableFromContext(mode, msgCtxt);
        if (mode == null || mode.equals("")) {
            throw new IllegalStateException("mode resolves to null or empty.");
        }
        return mode;
    }
    
    private String getPadding(MessageContext msgCtxt) throws Exception {
        String padding = this.properties.get("padding");
        if (padding == null || padding.equals("")) {
            return defaultCryptoPadding;
        }
        padding = CalloutUtil.resolveVariableFromContext(padding, msgCtxt);
        if (padding == null || padding.equals("")) {
            throw new IllegalStateException("padding resolves to null or empty.");
        }
        return padding;
    }
    
    private String getCipher(MessageContext msgCtxt) throws Exception {
        String cipher = (String) this.properties.get("cipher");
        if (cipher == null || cipher.equals("")) {
            return defaultCipherName + "/" + getMode(msgCtxt) + "/" + getPadding(msgCtxt);
        }
        cipher = CalloutUtil.resolveVariableFromContext(cipher, msgCtxt);
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
        if (flag == null || flag.equals("")) {
            return defaultValue;
        }
        flag = CalloutUtil.resolveVariableFromContext(flag, msgCtxt);
        if (flag == null || flag.equals("")) {
            return defaultValue;
        }
        return flag.equalsIgnoreCase(TRUE);
    }
    
    private EncodingType getEncodeResult(MessageContext msgCtxt) throws Exception {
        String encode = this.properties.get("encode-result");
        if (encode == null || encode.equals("")) {
            return EncodingType.NONE;
        }
        encode = CalloutUtil.resolveVariableFromContext(encode, msgCtxt);
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
        String encoded = Hex.encodeHexString(data);
        msgCtxt.setVariable(varName(name + "_hex"), encoded);
        encoded = Base64.encodeBase64String(data);
        msgCtxt.setVariable(varName(name + "_b64"), encoded);
    }

    private void setOutput(MessageContext msgCtxt, byte[] result) throws Exception {
        EncodingType outputEncodingWanted = getEncodeResult(msgCtxt);
        String outputVar = getOutputVar(msgCtxt);
        if (outputEncodingWanted == EncodingType.BASE64) {
            msgCtxt.setVariable(varName("output_encoding"), "base64");
            msgCtxt.setVariable(outputVar, Base64.encodeBase64String(result));
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

                emitEncodedOutput(msgCtxt,"salt", salt);
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
                source = decodeSource(msgCtxt, (String)source1);
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
