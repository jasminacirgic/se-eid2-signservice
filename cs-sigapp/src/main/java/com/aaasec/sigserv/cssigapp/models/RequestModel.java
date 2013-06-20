/*
 * Copyright 2013 Swedish E-identification Board (E-legitimationsnämnden)
 *  		 
 *   Licensed under the EUPL, Version 1.1 or ñ as soon they will be approved by the 
 *   European Commission - subsequent versions of the EUPL (the "Licence");
 *   You may not use this work except in compliance with the Licence. 
 *   You may obtain a copy of the Licence at:
 * 
 *   http://joinup.ec.europa.eu/software/page/eupl 
 * 
 *   Unless required by applicable law or agreed to in writing, software distributed 
 *   under the Licence is distributed on an "AS IS" basis,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
 *   implied.
 *   See the Licence for the specific language governing permissions and limitations 
 *   under the Licence.
 */
package com.aaasec.sigserv.cssigapp.models;

import com.aaasec.sigserv.cscommon.URLDecoder;
import com.aaasec.sigserv.cscommon.data.AuthData;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Model for HTTP requests
 */
public class RequestModel {

    private Map<String, String[]> verboseParameterMap;
    private Map<String, String> parameterMap = new HashMap<String, String>();
    private String action = "", id = "", parameter = "";
    private Map<String, List<String>> authAttributeMap;
    private AuthData authData;

    public RequestModel() {
    }

    public void setVerboseParameterMap(Map<String, String[]> verboseParameterMap) {
        this.verboseParameterMap = verboseParameterMap;

        // Get simplified parameter map containing just the first parameter string as map value
        parameterMap.clear();
        Set<String> keySet = verboseParameterMap.keySet();
        for (String key : keySet) {
            String[] qStrings = verboseParameterMap.get(key);
            if (qStrings.length > 0) {
                parameterMap.put(key, qStrings[0]);
            }
        }
        //Set standard request parameters
        if (parameterMap.containsKey("action")) {
            action = parameterMap.get("action");
        }
        if (parameterMap.containsKey("id")) {
            id = parameterMap.get("id");
        }
        if (parameterMap.containsKey("parameter")) {
            parameter = URLDecoder.queryDecode(parameterMap.get("parameter"));
        }
    }

    public Map<String, String> getParameterMap() {
        return parameterMap;
    }

    public Map<String, String[]> getVerboseParameterMap() {
        return verboseParameterMap;
    }

    public String getAction() {
        return action;
    }

    public String getId() {
        return id;
    }

    public String getParameter() {
        return parameter;
    }

    public Map<String, List<String>> getAuthAttributeMap() {
        return authAttributeMap;
    }

    public void setAuthAttributeMap(Map<String, List<String>> authAttributeMap) {
        this.authAttributeMap = authAttributeMap;
    }

    public AuthData getAuthData() {
        return authData;
    }

    public void setAuthData(AuthData authData) {
        this.authData = authData;
    }
}
