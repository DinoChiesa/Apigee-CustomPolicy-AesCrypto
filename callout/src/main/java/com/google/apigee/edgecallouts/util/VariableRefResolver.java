// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package com.google.apigee.edgecallouts.util;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Map;
import java.util.function.Function;

public class VariableRefResolver {
    private static final String variableReferencePatternString = "(.*?)\\{([^\\{\\} ]+?)\\}(.*?)";
    private static final Pattern variableReferencePattern = Pattern.compile(variableReferencePatternString);

    private Function<String,String> map;
    public VariableRefResolver(Function<String,String> map) {
        this.map = map;
    }

    private String get(String key) {
        String[] parts = key.split(":", 2);
        String result = map.apply(parts[0]);
        if ((result == null || result.equals("")) && parts.length > 1) {
            result = parts[1];
        }
        return result;
    }

    /**
     * Used to resolve dynamic runtime variables from the Apigee context.  If an inbound
     * string includes substrings surrounded by curly braces, that is interpreted as a
     * reference to a context variable and the reference is replaced with a value
     * retrieved from the context.
     *
     * @param spec The variable name to be resolved
     * @param map The VariableResolver
     * @return The resolved variable value
     */
    public String resolve(String spec) {
        Matcher matcher = variableReferencePattern.matcher(spec);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            matcher.appendReplacement(sb, "");
            sb.append(matcher.group(1));
            sb.append(get(matcher.group(2)));
            sb.append(matcher.group(3));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }
}
