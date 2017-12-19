// CalloutUtil.java
//
// This is a utility class for custom policies in Apigee Edge.
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

package com.google.apigee.edgecallouts.util;

import com.apigee.flow.message.MessageContext;
import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.Collections;

public final class CalloutUtil {

    public static Map<String,String> genericizeMap(Map properties) {
        // convert an untyped Map to a generic map
        Map<String,String> m = new HashMap<String,String>();
        Iterator iterator =  properties.keySet().iterator();
        while(iterator.hasNext()){
            Object key = iterator.next();
            Object value = properties.get(key);
            if ((key instanceof String) && (value instanceof String)) {
                m.put((String) key, (String) value);
            }
        }
        return Collections.unmodifiableMap(m);
    }

    public static String getHeaderWithCommas(MessageContext msgCtxt, String headerName) {
        ArrayList list = msgCtxt.getVariable("request.header." + headerName + ".values");
        return StringUtils.join(list,",");
    }

    /**
     * Strips all leading and trailing characters from the given string.
     * Does NOT strip characters in the middle, and strips the leading and
     * trailing characters respectively.
     * e.g. "{abc}", "{", "}" returns "abc"
     * e.g. "aabccxyz", "ba", "z" returns "ccxy"
     *
     * @param toStrip  The String to remove characters from
     * @param start  The characters to remove from the start (in any order)
     * @param end The characters to remove from the end (in any order)
     * @return String with leading and trailing characters stripped
     */
    public static String stripStartAndEnd(String toStrip, String start, String end) {
        if(StringUtils.isBlank(toStrip)) {
            throw new IllegalArgumentException("toStrip must not be blank or null");
        }
        return StringUtils.stripEnd(StringUtils.stripStart(toStrip, start), end);
    }

}
