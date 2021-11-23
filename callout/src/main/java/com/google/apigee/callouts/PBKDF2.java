// PBKDF2.java
//
// Copyright (c) 2021 Google LLC.
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
import com.google.apigee.util.PasswordUtil;
import java.util.Base64;
import java.util.Map;

@IOIntensive
public class PBKDF2 extends CalloutBase implements Execution {
  private static final int maxPbkdf2Iterations = 2560000;
  private static final int minPbkdf2Iterations = 1;

  public PBKDF2(Map properties) {
    super(properties);
  }

  String getVarPrefix() {
    return "pbkdf2_";
  };

  private byte[] getSalt(MessageContext msgCtxt) throws Exception {
    byte[] result = _getByteArrayProperty(msgCtxt, "salt");
    if (result == null) {
      throw new IllegalStateException("you must specify a value for salt.");
    }
    return result;
  }

  private PasswordUtil.PRF getPseudoRandomFunction(MessageContext msgCtxt) throws Exception {
    String prfString = this.properties.get("prf");
    if (prfString != null) prfString = prfString.trim();
    if (prfString == null || prfString.equals("")) {
      throw new IllegalStateException("you must specify a value for the PRF function.");
    }
    prfString = resolveVariableReferences(prfString, msgCtxt);
    return PasswordUtil.PRF.valueOf(prfString.toUpperCase().replaceAll("-", ""));
  }

  private int getDesiredOutputByteLength(MessageContext msgCtxt) throws Exception {
    String dklenString = _getOptionalString(msgCtxt, "dklen");
    if (dklenString == null || dklenString.equals("")) {
      throw new IllegalStateException("you must specify a value for dklen.");
    }
    int dklen = Integer.parseInt(dklenString);
    if (dklen < 20 || dklen > 4096)
      throw new IllegalStateException("the value for dklen is out of range.");
    return dklen;
  }

  private int getIterationCount(MessageContext msgCtxt) throws Exception {
    String iterationsString = _getOptionalString(msgCtxt, "iterations");
    if (iterationsString == null || iterationsString.equals("")) {
      throw new IllegalStateException("you must specify a value for iterations.");
    }
    int iterations = Integer.parseInt(iterationsString);
    if (iterations < minPbkdf2Iterations || iterations > maxPbkdf2Iterations)
      throw new IllegalStateException("the value for PBKDF2 iteration count is out of range.");
    return iterations;
  }

  private String getOutputVar(MessageContext msgCtxt) throws Exception {
    return _getStringProp(msgCtxt, "output", "output");
  }

  private String getExpected(MessageContext msgCtxt) throws Exception {
    return _getOptionalString(msgCtxt, "expected");
  }

  private String getPassphrase(MessageContext msgCtxt) throws Exception {
    String passphrase = _getStringProp(msgCtxt, "passphrase", null);
    if (passphrase == null) {
      throw new IllegalStateException("passphrase resolves to null or empty.");
    }
    return passphrase;
  }

  private boolean getRaiseFaultOnNoMatch(MessageContext msgCtxt) throws Exception {
    return _getBooleanProperty(msgCtxt, "raise-fault-on-no-match", false);
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = false;
    try {
      clearVariables(msgCtxt);
      debug = getDebug(msgCtxt);
      PasswordUtil.PRF prf = getPseudoRandomFunction(msgCtxt);
      String passphrase = getPassphrase(msgCtxt);
      int iterations = getIterationCount(msgCtxt);
      int dklen = getDesiredOutputByteLength(msgCtxt);
      byte[] salt = getSalt(msgCtxt);
      PasswordUtil.KeyAndIv params =
          PasswordUtil.deriveKeyAndIv(passphrase, salt, dklen * 8, dklen * 8, iterations, prf);
      byte[] output = params.getKey();
      emitEncodedOutput(msgCtxt, "output", output);
      String outputBase64Encoded = Base64.getEncoder().encodeToString(output);
      String expectedBase64Encoded = getExpected(msgCtxt);
      if (expectedBase64Encoded != null) {
        // want to perform a check
        if (!outputBase64Encoded.equals(expectedBase64Encoded)) {
          msgCtxt.setVariable(varName("error"), "no match");

          if (getRaiseFaultOnNoMatch(msgCtxt)) return ExecutionResult.ABORT;
        }
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
