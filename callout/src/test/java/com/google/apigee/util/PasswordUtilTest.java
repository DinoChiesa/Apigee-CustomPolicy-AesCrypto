// PasswordUtilTest.java
//
// Copyright (c) 2021 Google LLC
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

package com.google.apigee.util;

import com.google.apigee.encoding.Base16;
import java.nio.charset.StandardCharsets;
import org.testng.Assert;
import org.testng.annotations.Test;

public class PasswordUtilTest {

  private static String normalize(String s) {
    return s.replaceAll(" ", "");
  }

  @Test()
  public void rfc6070_section2_vector1() {
    String plainPassword = "password";
    byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
    int iterations = 1;
    int keyBits = 20 * 8;
    int ivBits = 20 * 8;
    String expectedResult =
        normalize("0c 60 c8 0f 96 1f 0e 71" + "f3 a9 b5 24 af 60 12 06" + "2f e0 37 a6");

    PasswordUtil.PRF prf = PasswordUtil.PRF.valueOf("HMACSHA1");
    PasswordUtil.KeyAndIv output =
        PasswordUtil.deriveKeyAndIv(plainPassword, salt, keyBits, ivBits, iterations, prf);
    byte[] key = output.getKey();
    String encodedKey = Base16.encode(key);
    Assert.assertEquals(encodedKey, expectedResult);
  }

  @Test()
  public void rfc6070_section2_vector2() {
    String plainPassword = "password";
    byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
    int iterations = 2;
    int keyBits = 20 * 8;
    int ivBits = 20 * 8;
    String expectedResult =
        normalize("ea 6c 01 4d c7 2d 6f 8c" + "cd 1e d9 2a ce 1d 41 f0" + "d8 de 89 57");

    PasswordUtil.PRF prf = PasswordUtil.PRF.valueOf("HMACSHA1");
    PasswordUtil.KeyAndIv output =
        PasswordUtil.deriveKeyAndIv(plainPassword, salt, keyBits, ivBits, iterations, prf);
    byte[] key = output.getKey();
    String encodedKey = Base16.encode(key);
    Assert.assertEquals(encodedKey, expectedResult);
  }

  @Test()
  public void rfc6070_section2_vector3() {
    String plainPassword = "password";
    byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
    int iterations = 4096;
    int keyBits = 20 * 8;
    int ivBits = 20 * 8;
    String expectedResult =
        normalize("4b 00 79 01 b7 65 48 9a" + "be ad 49 d9 26 f7 21 d0" + "65 a4 29 c1");
    PasswordUtil.PRF prf = PasswordUtil.PRF.valueOf("HMACSHA1");
    PasswordUtil.KeyAndIv output =
        PasswordUtil.deriveKeyAndIv(plainPassword, salt, keyBits, ivBits, iterations, prf);
    byte[] key = output.getKey();
    String encodedKey = Base16.encode(key);
    Assert.assertEquals(encodedKey, expectedResult);
  }

  @Test()
  public void rfc6070_section2_vector4() {
    String plainPassword = "password";
    byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
    int iterations = 16777216; // will require >20s on MBP 2018
    int keyBits = 20 * 8;
    int ivBits = 20 * 8;
    String expectedResult =
        normalize("ee fe 3d 61 cd 4d a4 e4" + "e9 94 5b 3d 6b a2 15 8c" + "26 34 e9 84");
    PasswordUtil.PRF prf = PasswordUtil.PRF.valueOf("HMACSHA1");
    PasswordUtil.KeyAndIv output =
        PasswordUtil.deriveKeyAndIv(plainPassword, salt, keyBits, ivBits, iterations, prf);
    byte[] key = output.getKey();
    String encodedKey = Base16.encode(key);
    Assert.assertEquals(encodedKey, expectedResult);
  }

  @Test()
  public void rfc6070_section2_vector5() {
    String plainPassword = "passwordPASSWORDpassword";
    byte[] salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(StandardCharsets.UTF_8);
    int iterations = 4096;
    int keyBits = 25 * 8;
    int ivBits = 25 * 8;
    String expectedResult =
        normalize(
            "3d 2e ec 4f e4 1c 84 9b"
                + "80 c8 d8 36 62 c0 e4 4a"
                + "8b 29 1a 96 4c f2 f0 70"
                + "38");
    PasswordUtil.PRF prf = PasswordUtil.PRF.valueOf("HMACSHA1");
    PasswordUtil.KeyAndIv output =
        PasswordUtil.deriveKeyAndIv(plainPassword, salt, keyBits, ivBits, iterations, prf);
    byte[] key = output.getKey();
    String encodedKey = Base16.encode(key);
    Assert.assertEquals(encodedKey, expectedResult);
  }

  @Test()
  public void rfc7914_section11_vector1() {
    String plainPassword = "passwd";
    byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
    int iterations = 1;
    int keyBits = 64 * 8;
    int ivBits = 64 * 8;
    String expectedResult =
        normalize(
            "55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05"
                + "f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc"
                + "49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31"
                + "7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83");

    PasswordUtil.PRF prf = PasswordUtil.PRF.valueOf("HMACSHA256");
    PasswordUtil.KeyAndIv output =
        PasswordUtil.deriveKeyAndIv(plainPassword, salt, keyBits, ivBits, iterations, prf);
    byte[] key = output.getKey();
    String encodedKey = Base16.encode(key);
    // System.out.printf("actual: %s\n", encodedKey);
    // System.out.printf("expect: %s\n", expectedResult);
    Assert.assertEquals(encodedKey, expectedResult);
  }

  @Test()
  public void rfc7914_section11_vector2() {
    String plainPassword = "Password";
    byte[] salt = "NaCl".getBytes(StandardCharsets.UTF_8);
    int iterations = 80000;
    int keyBits = 64 * 8;
    int ivBits = 64 * 8;
    String expectedResult =
        normalize(
            "4d dc d8 f6 0b 98 be 21 83 0c ee 5e f2 27 01 f9"
                + "64 1a 44 18 d0 4c 04 14 ae ff 08 87 6b 34 ab 56"
                + "a1 d4 25 a1 22 58 33 54 9a db 84 1b 51 c9 b3 17"
                + "6a 27 2b de bb a1 d0 78 47 8f 62 b3 97 f3 3c 8d");
    PasswordUtil.PRF prf = PasswordUtil.PRF.valueOf("HMACSHA256");

    PasswordUtil.KeyAndIv output =
        PasswordUtil.deriveKeyAndIv(plainPassword, salt, keyBits, ivBits, iterations, prf);
    byte[] key = output.getKey();
    String encodedKey = Base16.encode(key);
    // System.out.printf("actual: %s\n", encodedKey);
    // System.out.printf("expect: %s\n", expectedResult);
    Assert.assertEquals(encodedKey, expectedResult);
  }
}
