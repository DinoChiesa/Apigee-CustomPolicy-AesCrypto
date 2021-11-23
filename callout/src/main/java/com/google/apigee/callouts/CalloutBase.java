// CalloutBase.java
//
// Copyright (c) 2018-2021 Google LLC.
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

import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.encoding.Base16;
import com.google.apigee.util.CalloutUtil;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@IOIntensive
public abstract class CalloutBase {
  private static final Pattern variableReferencePattern =
      Pattern.compile("(.*?)\\{([^\\{\\} :][^\\{\\} ]*?)\\}(.*?)");
  private static final Pattern commonErrorPattern = Pattern.compile("^(.+?)[:;] (.+)$");

  abstract String getVarPrefix();

  protected final Map<String, String> properties;

  enum EncodingType {
    NONE,
    BASE64,
    BASE64URL,
    BASE16,
    HEX
  };

  public CalloutBase(Map properties) {
    this.properties = CalloutUtil.genericizeMap(properties);
  }

  protected String varName(String s) {
    return getVarPrefix() + s;
  }

  protected String resolveVariableReferences(String spec, MessageContext msgCtxt) {
    if (spec == null || spec.equals("")) return spec;
    Matcher matcher = variableReferencePattern.matcher(spec);
    StringBuffer sb = new StringBuffer();
    while (matcher.find()) {
      matcher.appendReplacement(sb, "");
      sb.append(matcher.group(1));
      String ref = matcher.group(2);
      String[] parts = ref.split(":", 2);
      Object v = msgCtxt.getVariable(parts[0]);
      if (v != null) {
        sb.append(v.toString());
      } else if (parts.length > 1) {
        sb.append(parts[1]);
      }
      sb.append(matcher.group(3));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  protected EncodingType _getEncodingTypeProperty(MessageContext msgCtxt, String propName)
      throws Exception {
    return EncodingType.valueOf(_getStringProp(msgCtxt, propName, "NONE").toUpperCase());
  }

  protected byte[] _getByteArrayProperty(MessageContext msgCtxt, String propName) throws Exception {
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

  protected byte[] decodeString(String s, EncodingType decodingKind) throws Exception {
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

  protected String _getStringProp(MessageContext msgCtxt, String name, String defaultValue)
      throws Exception {
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

  protected String _getRequiredString(MessageContext msgCtxt, String name) throws Exception {
    String value = _getStringProp(msgCtxt, name, null);
    if (value == null)
      throw new IllegalStateException(String.format("%s resolves to null or empty.", name));
    return value;
  }

  protected String _getOptionalString(MessageContext msgCtxt, String name) throws Exception {
    return _getStringProp(msgCtxt, name, null);
  }

  protected boolean _getBooleanProperty(
      MessageContext msgCtxt, String propName, boolean defaultValue) throws Exception {
    String flag = this.properties.get(propName);
    if (flag != null) flag = flag.trim();
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    flag = resolveVariableReferences(flag, msgCtxt);
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    return flag.equalsIgnoreCase("true");
  }

  protected void clearVariables(MessageContext msgCtxt) {
    msgCtxt.removeVariable(varName("error"));
    msgCtxt.removeVariable(varName("output"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
  }

  protected boolean getDebug(MessageContext msgCtxt) throws Exception {
    return _getBooleanProperty(msgCtxt, "debug", false);
  }

  protected void emitEncodedOutput(MessageContext msgCtxt, String name, byte[] data) {
    String encoded = Base16.encode(data);
    msgCtxt.setVariable(varName(name + "_b16"), encoded);
    encoded = Base64.getUrlEncoder().encodeToString(data);
    msgCtxt.setVariable(varName(name + "_b64url"), encoded);
    encoded = Base64.getEncoder().encodeToString(data);
    msgCtxt.setVariable(varName(name + "_b64"), encoded);
  }

  protected static String getStackTraceAsString(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    return sw.toString();
  }

  protected void setExceptionVariables(Exception exc1, MessageContext msgCtxt) {
    String error = exc1.toString().replaceAll("\n", " ");
    msgCtxt.setVariable(varName("exception"), error);
    Matcher matcher = commonErrorPattern.matcher(error);
    if (matcher.matches()) {
      msgCtxt.setVariable(varName("error"), matcher.group(2));
    } else {
      msgCtxt.setVariable(varName("error"), error);
    }
  }
}
