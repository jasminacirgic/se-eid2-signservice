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
package com.aaasec.sigserv.sigserver;

import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.DerefUrl;
import com.aaasec.sigserv.cssigapp.models.RequestModel;
import java.io.ByteArrayInputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import x0Assertion.oasisNamesTcSAML2.AssertionDocument;

/**
 * Factory for HTML request models
 */
public class RequestModelFactory implements Constants {

    private static final List<String> shibAttrList = Arrays.asList(SHIB_ATTRIBUTE_IDs);
    private static final List<String> attrList = Arrays.asList(ATTRIBUTE_IDs);
    java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("infoText");

    public RequestModelFactory() {
    }

    public RequestModel getRequestModel(HttpServletRequest request) {
        RequestModel req = new RequestModel();
        getAuthData(request, req);

        try {
            req.setVerboseParameterMap(request.getParameterMap());
            return req;
        } catch (Exception ex) {
            return null;
        }
    }

    private void getAuthData(HttpServletRequest request, RequestModel req) {
        Map<String, List<String>> attrMap = new HashMap<String, List<String>>();
        List<List<String>> contextAttr = new ArrayList<List<String>>();
        List<List<String>> idAttr = new ArrayList<List<String>>();
        String authType = (request.getAuthType() != null) ? utf8(request.getAuthType()) : "";
        String remoteUser = (request.getRemoteUser() != null) ? utf8(request.getRemoteUser()) : "";

        for (String attr : shibAttrList) {
            if (request.getAttribute(attr) != null) {
                List<String> attrInfoList = getAttrInfoList(attr, request.getAttribute(attr));
                contextAttr.add(attrInfoList);
                attrMap.put(attr, attrInfoList);
            }
        }
        for (String attr : attrList) {
            if (request.getAttribute(attr) != null) {
                List<String> attrInfoList = getAttrInfoList(attr, request.getAttribute(attr));
                idAttr.add(attrInfoList);
                attrMap.put(attr, attrInfoList);
            }
        }


//        Enumeration<String> attributeNames = request.getAttributeNames();
//
//        while (attributeNames.hasMoreElements()) {
//            String attr = attributeNames.nextElement();
//            if (shibAttrList.contains(attr)) {
//                List<String> attrInfoList = getAttrInfoList(attr, request.getAttribute(attr));
//                contextAttr.add(attrInfoList);
//                attrMap.put(attr, attrInfoList);
//            }
//            if (attrList.contains(attr)) {
//                List<String> attrInfoList = getAttrInfoList(attr, request.getAttribute(attr));
//                idAttr.add(attrInfoList);
//                attrMap.put(attr, attrInfoList);
//            }
//        }

        String idpId = (attrMap.containsKey("Shib-Identity-Provider")) ? attrMap.get("Shib-Identity-Provider").get(2) : "";
        String idAttribute = "", id = "";
        for (String ida : ID_ATTRIBUTES) {
            if (attrMap.containsKey(ida)) {
                idAttribute = attrMap.get(ida).get(0);
                id = attrMap.get(ida).get(2);
                break;
            }
        }

        AuthData authData = new AuthData(authType, remoteUser, contextAttr, idAttr, idpId, idAttribute, id);
        req.setAuthData(authData);
        req.setAuthAttributeMap(attrMap);
        // Finally, get assertion URL:s
        Enumeration<String> attributeNames = request.getAttributeNames();
        int assertionCount = 0;
        Object ac = request.getAttribute(SHIB_ASSERTION_COUNT);
        try {
            assertionCount = Integer.parseInt((String) ac);
            assertionCount = assertionCount > 9 ? 9 : assertionCount;
            ArrayList<byte[]> assertions = authData.getAssertions();

            for (int i = 0; i < assertionCount; i++) {
                String assertId = ASSERION_LOC_PREFIX + String.valueOf(i+1);
                String urlStr = (String) request.getAttribute(assertId);
                URL assertionUrl = new URL(urlStr);
                byte[] bytes = DerefUrl.getBytes(assertionUrl);
                AssertionDocument assertion = AssertionDocument.Factory.parse(new ByteArrayInputStream(bytes));
                assertions.add(bytes);                
                
//                Logger.getLogger(RequestModelFactory.class.getName()).info(assertionURLs.get(i));
//                byte[] asBytes = DerefUrl.getBytes(new URL(assertionURLs.get(i)));
//                String assertion = new String(asBytes, Charset.forName("UTF-8"));
//                int xxxx=0;
            }
            authData.setAssertions(assertions);
        } catch (Exception ex) {
        }
    }

    private List<String> getAttrInfoList(String attr, Object attrObject) {
        String attrValue = (attrObject instanceof String) ? utf8((String) attrObject) : utf8(attrObject.toString());
        List<String> valueList = new ArrayList<String>();
        valueList.add(attr);
        valueList.add(getInfoText(attr));
        valueList.add(attrValue);
        return valueList;
    }

    private String getInfoText(String str) {
        String infoTxt = str;
        try {
            infoTxt = bundle.getString(str);
        } catch (Exception ex) {
        }
        return infoTxt;
    }

    private static String utf8(String isoStr) {
        if (isoStr == null) {
            return "";
        }
        byte[] bytes = isoStr.getBytes(Charset.forName("ISO-8859-1"));
        return new String(bytes, Charset.forName("UTF-8"));
    }
}
