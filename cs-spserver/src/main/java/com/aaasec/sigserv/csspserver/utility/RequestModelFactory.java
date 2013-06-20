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
package com.aaasec.sigserv.csspserver.utility;

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.cscommon.enums.Enums;
import com.aaasec.sigserv.csspserver.models.RequestModel;
import com.aaasec.sigserv.csspserver.models.SpSession;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * HTTP Request model factory.
 */
public class RequestModelFactory implements Constants {

    private static final List<String> shibAttrList = Arrays.asList(SHIB_ATTRIBUTE_IDs);
    private static final List<String> attrList = Arrays.asList(ATTRIBUTE_IDs);
    private ResourceBundle infoText = ResourceBundle.getBundle("infoText");

    public RequestModelFactory() {
    }

    public RequestModel getRequestModel(HttpServletRequest request, SpSession session) {
        RequestModel req = new RequestModel();

        String sigResponse = request.getParameter("EidSignResponse");
        String binding = request.getParameter("Binding");
        String nonce = request.getParameter("RelayState");

        req.setSigResponse(sigResponse != null ? sigResponse : "");
        session.setReqSigAlgorithm(getRequestedAlgorithm(request));
        getAuthData(request, req);

        // set session parameters
        AuthData ad = req.getAuthData();
        session.setIdpEntityId(ad.getIdpEntityID());
        session.setSignerAttribute(getAttrOidString(ad.getIdAttribute()));
        session.setSignerId(ad.getId());

        try {
            req.setVerboseParameterMap(request.getParameterMap(), session);
            return req;
        } catch (Exception ex) {
            return null;
        }



    }

    public static String getAttrOidString(String idAttribute) {
        try {
            return Enums.idAttributes.get(idAttribute);
        } catch (Exception ex) {
            return "";
        }

    }

    private void getAuthData(HttpServletRequest request, RequestModel req) {
        Map<String, List<String>> attrMap = new HashMap<String, List<String>>();
        List<List<String>> contextAttr = new ArrayList<List<String>>();
        List<List<String>> idAttr = new ArrayList<List<String>>();
        String authType = (request.getAuthType() != null) ? utf8(request.getAuthType()) : "";
        String remoteUser = (request.getRemoteUser() != null) ? utf8(request.getRemoteUser()) : "";

        List<String> attrNameList = new ArrayList<String>();
        Enumeration<String> attributeNames = request.getAttributeNames();
        while (attributeNames.hasMoreElements()) {
            attrNameList.add(attributeNames.nextElement());
        }

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
            infoTxt = infoText.getString(str);
        } catch (Exception ex) {
        }
        return infoTxt;
    }

    private String getRequestedAlgorithm(HttpServletRequest request) {
        String reqAlgo = SIGNATURE_ALGORITHMS[0];
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie ck : cookies) {
                if (ck.getName().equalsIgnoreCase("sigAlgo")) {
                    try {
                        int algoIdx = Integer.parseInt(ck.getValue());
                        reqAlgo = SIGNATURE_ALGORITHMS[algoIdx];
                    } catch (Exception ex) {
                    }
                }
            }
        }
        return reqAlgo;
    }

    private static String utf8(String isoStr) {
        if (isoStr == null) {
            return "";
        }
        byte[] bytes = isoStr.getBytes(Charset.forName("ISO-8859-1"));
        return new String(bytes, Charset.forName("UTF-8"));
    }
}
