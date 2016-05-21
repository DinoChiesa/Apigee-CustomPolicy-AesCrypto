package com.dinochiesa.edgecallouts.util;

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

    /**
     * Used to resolve dynamic runtime variables from the Apigee context.
     * If a variable is surrounded with curly braces, it is interpreted
     * as a dynamic variable and the value is looked up in the context.
     * Otherwise, it returns the value passed in.
     * @param variableName The variable name to be resolved
     * @param ctx The Apigee context object
     * @return The resolved variable value
     */
    public static String resolveVariableFromContext(String variableName, MessageContext ctx) {
        if (StringUtils.isBlank(variableName)) {
            throw new IllegalArgumentException("variableName may not be null or empty");
        }
        if(ctx == null) {
            throw new IllegalStateException("Message context may not be null");
        }
        if (variableName.startsWith("{") && variableName.endsWith("}") && variableName.indexOf(" ") == -1)
            return ctx.getVariable(stripStartAndEnd(variableName, "{", "}"));
        return variableName;
    }

}
