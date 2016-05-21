
package com.dinochiesa.edgecallouts.util;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.crypto.digests.SHA3Digest;

public class PasswordUtil {

    private static final DigestRandomGenerator prng = new DigestRandomGenerator(new SHA3Digest(512));

    public static class KeyAndIv {
        public KeyAndIv(byte[] key, byte[] iv) {
            _iv = iv;
            _key = key;
        }
        private byte[] _key;
        private byte[] _iv;
        public byte[] getKey() { return _key; }
        public byte[] getIV() { return _iv; }
    }

    private PasswordUtil() {}

    public static KeyAndIv deriveKeyAndIv(String plainPassword, byte[] salt, int keyBits, int ivBits, int iterations) {
        // Derive keys and IVs from passwords, as defined by PKCS 5 V2.0 Scheme
        // 2. This generator uses a SHA-1 HMac as the
        // calculation function. This is also known as PBKDF2, and is defined in RFC2898.
        // See https://en.wikipedia.org/wiki/PBKDF2
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(plainPassword.getBytes(StandardCharsets.UTF_8),
                       salt,
                       iterations);
        ParametersWithIV params = (ParametersWithIV) generator.generateDerivedParameters(keyBits, ivBits);
        return new KeyAndIv(((KeyParameter)params.getParameters()).getKey(), params.getIV());
    }

    public static byte[] generateSalt(int count) {
        byte[] salt = new byte[count/8]; // in bits
        prng.nextBytes(salt);
        return salt;
    }

}

