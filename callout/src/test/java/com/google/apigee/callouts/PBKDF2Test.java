// PBKDF2Test.java
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

package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionResult;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.Test;

public class PBKDF2Test extends TestBase {

  @Test()
  public void vector1() {
    String expectedOutput = "efWe1q58Y62aLWyvn7MpNlI4bDWPQHK2yUg+jxPMsKQ=";
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "vector1");
    properties.put("passphrase", "Melo_123");
    properties.put("iterations", "30000");
    properties.put("dklen", "32");
    properties.put("salt", "TSKRGzW5dWMC");
    properties.put("prf", "HMAC-SHA256");

    PBKDF2 callout = new PBKDF2(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("pbkdf2_error");
    if (error != null) System.out.println("error: " + error);

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertNull(error);

    String output = msgCtxt.getVariable("pbkdf2_output_b64");
    // System.out.printf("output: %s\n", output);
    // System.out.printf("expect: %s\n", expectedOutput);
    Assert.assertEquals(output, expectedOutput);
  }

  @Test()
  public void vector1_expected_success() {
    String expectedOutput = "efWe1q58Y62aLWyvn7MpNlI4bDWPQHK2yUg+jxPMsKQ=";
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "vector1_expected_success");
    properties.put("passphrase", "Melo_123");
    properties.put("iterations", "30000");
    properties.put("dklen", "32");
    properties.put("salt", "TSKRGzW5dWMC");
    properties.put("prf", "HMAC-SHA256");
    properties.put("expected", expectedOutput);

    PBKDF2 callout = new PBKDF2(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("pbkdf2_error");
    if (error != null) System.out.println("error: " + error);

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertNull(error);

    String output = msgCtxt.getVariable("pbkdf2_output_b64");
    // System.out.printf("output: %s\n", output);
    // System.out.printf("expect: %s\n", expectedOutput);
    Assert.assertEquals(output, expectedOutput);
  }

  @Test()
  public void vector1_expected_fail() {
    String expectedOutput = "efWe1q58Y62aLWyvn7MpNlI4bDWPQHK2yUg+jxPMsKQ=";
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "vector1_expected_fail");
    properties.put("passphrase", "Melo_123");
    properties.put("iterations", "30000");
    properties.put("dklen", "32");
    properties.put("salt", "TSKRGzW5dWMC");
    properties.put("prf", "HMAC-SHA256");
    properties.put("raise-fault-on-no-match", "true");
    properties.put("expected", "wrong-expected-output");

    PBKDF2 callout = new PBKDF2(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("pbkdf2_error");
    if (error != null) System.out.println("error: " + error);

    Assert.assertEquals(result, ExecutionResult.ABORT);
    Assert.assertEquals(error, "no match");

    String output = msgCtxt.getVariable("pbkdf2_output_b64");
    // System.out.printf("output: %s\n", output);
    // System.out.printf("expect: %s\n", expectedOutput);
    Assert.assertEquals(output, expectedOutput);
  }

  @Test()
  public void missing_prf_fail() {
    String expectedOutput = "efWe1q58Y62aLWyvn7MpNlI4bDWPQHK2yUg+jxPMsKQ=";
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "missing_prf_fail");
    properties.put("passphrase", "Melo_123");
    properties.put("iterations", "30000");
    properties.put("dklen", "32");
    // properties.put("prf", "HMAC-SHA256");
    properties.put("salt", "TSKRGzW5dWMC");

    PBKDF2 callout = new PBKDF2(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("pbkdf2_error");
    if (error != null) System.out.println("error: " + error);

    Assert.assertEquals(result, ExecutionResult.ABORT);
    Assert.assertEquals(error, "you must specify a value for the PRF function.");

    String output = msgCtxt.getVariable("pbkdf2_output_b64");
    Assert.assertNull(output);
  }

  @Test()
  public void missing_dklen_fail() {
    String expectedOutput = "efWe1q58Y62aLWyvn7MpNlI4bDWPQHK2yUg+jxPMsKQ=";
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "missing_prf_fail");
    properties.put("passphrase", "Melo_123");
    properties.put("iterations", "30000");
    // properties.put("dklen", "32");
    properties.put("salt", "TSKRGzW5dWMC");
    properties.put("prf", "HMAC-SHA256");

    PBKDF2 callout = new PBKDF2(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("pbkdf2_error");
    if (error != null) System.out.println("error: " + error);

    Assert.assertEquals(result, ExecutionResult.ABORT);
    Assert.assertEquals(error, "you must specify a value for dklen.");

    String output = msgCtxt.getVariable("pbkdf2_output_b64");
    Assert.assertNull(output);
  }

  @Test()
  public void missing_salt_fail() {
    String expectedOutput = "efWe1q58Y62aLWyvn7MpNlI4bDWPQHK2yUg+jxPMsKQ=";
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "missing_salt_fail");
    properties.put("passphrase", "Melo_123");
    properties.put("iterations", "30000");
    properties.put("dklen", "32");
    // properties.put("salt", "TSKRGzW5dWMC");
    properties.put("prf", "HMAC-SHA256");

    PBKDF2 callout = new PBKDF2(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("pbkdf2_error");
    if (error != null) System.out.println("error: " + error);

    Assert.assertEquals(result, ExecutionResult.ABORT);
    Assert.assertEquals(error, "you must specify a value for salt.");

    String output = msgCtxt.getVariable("pbkdf2_output_b64");
    Assert.assertNull(output);
  }

  @Test()
  public void missing_iterations_fail() {
    String expectedOutput = "efWe1q58Y62aLWyvn7MpNlI4bDWPQHK2yUg+jxPMsKQ=";
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "missing_prf_fail");
    properties.put("passphrase", "Melo_123");
    // properties.put("iterations", "30000");
    properties.put("dklen", "32");
    properties.put("salt", "TSKRGzW5dWMC");
    properties.put("prf", "HMAC-SHA256");

    PBKDF2 callout = new PBKDF2(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("pbkdf2_error");
    if (error != null) System.out.println("error: " + error);

    Assert.assertEquals(result, ExecutionResult.ABORT);
    Assert.assertEquals(error, "you must specify a value for iterations.");

    String output = msgCtxt.getVariable("pbkdf2_output_b64");
    Assert.assertNull(output);
  }
}
