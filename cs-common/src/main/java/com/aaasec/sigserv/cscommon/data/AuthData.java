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
package com.aaasec.sigserv.cscommon.data;

import com.aaasec.sigserv.cscommon.enums.Enums;
import com.aaasec.sigserv.cscommon.enums.Enums.ShibAttribute;
import java.io.ByteArrayInputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;
import se.elegnamnden.id.authCont.x10.saci.AttributeMappingType;
import se.elegnamnden.id.authCont.x10.saci.AuthContextInfoType;
import se.elegnamnden.id.authCont.x10.saci.IdAttributesType;
import se.elegnamnden.id.authCont.x10.saci.SAMLAuthContextDocument;
import se.elegnamnden.id.authCont.x10.saci.SAMLAuthContextType;
import se.elegnamnden.id.csig.x10.dssExt.ns.ContextInfoType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignerAssertionInfoType;
import x0Assertion.oasisNamesTcSAML2.AssertionDocument;
import x0Assertion.oasisNamesTcSAML2.AssertionType;
import x0Assertion.oasisNamesTcSAML2.AttributeStatementType;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0Assertion.oasisNamesTcSAML2.NameIDType;

/**
 * Class for user authentication data.
 */
public class AuthData {

    private String authType, remoteUser;
    private List<List<String>> context, attribute;
    private String idpEntityID, idAttribute, id;
    private SignerAssertionInfoType userAssertionInfo;
    private ArrayList<byte[]> assertions = new ArrayList<byte[]>();

    public AuthData(String authType, String remoteUser, List<List<String>> context, List<List<String>> attribute, String idpEntityID, String idAttribute, String id) {
        this.authType = authType;
        this.remoteUser = remoteUser;
        this.context = context;
        this.attribute = attribute;
        this.idpEntityID = idpEntityID;
        this.idAttribute = idAttribute;
        this.id = id;
    }

    public SignerAssertionInfoType getUserAssertion() {
        userAssertionInfo = SignerAssertionInfoType.Factory.newInstance();
        ContextInfoType samlCont = userAssertionInfo.addNewContextInfo();
        AttributeStatementType samlUser = userAssertionInfo.addNewAttributeStatement();

        if (idpEntityID.length() == 0
                || authType.length() == 0
                || idAttribute.length() == 0
                || id.length() == 0) {
            return userAssertionInfo;
        }


        samlCont.setAuthType(authType);
        if (!assertions.isEmpty()) {
            try {
                AssertionType assertion = getAssertioinDocument(0).getAssertion();
                Calendar authnInstant = assertion.getAuthnStatementArray(0).getAuthnInstant();
                samlCont.setAuthenticationInstant(authnInstant);
                samlCont.setAssertionRef(assertion.getID());
            } catch (Exception ex) {
            }
        }
        for (List<String> cont : context) {
            String aid = cont.get(0);
            ShibAttribute attr = Enums.ShibAttribute.getAttributeByName(aid);
            if (attr != null) {
                switch (attr) {
                    case ContextClassRef:
                        samlCont.setAuthnContextClassRef(cont.get(2));
                        break;
                    case IdentityProvider:
                        NameIDType idp = samlCont.addNewIdentityProvider();
                        idp.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
                        idp.setStringValue(cont.get(2));
                        break;
                    case ApplicationID:
                        samlCont.setServiceID(cont.get(2));
                        break;
                    default:
                }
            }
        }
//        HashMap<String, String> ca = Enums.contextAttributes;
//        samlCont.setAuthType(authType);
//        for (List<String> cont : context) {
//            String aid = cont.get(0);
//            if (ca.containsKey(aid)) {
//                addAttribute(samlCont, ca.get(aid), cont.get(1), cont.get(2));
//            }
//        }


        for (List<String> user : attribute) {
            String aid = user.get(0);
            try {
                String aurn = "urn:oid:" + Enums.idAttributes.get(aid);
                addAttribute(samlUser, aurn, user.get(1), user.get(2));
            } catch (Exception ex) {
            }
        }

        return userAssertionInfo;
    }

    public SAMLAuthContextDocument getSimpleAssertionInfo() {
        SAMLAuthContextDocument assertionInfoDoc = SAMLAuthContextDocument.Factory.newInstance();
        SAMLAuthContextType assertionInfo = assertionInfoDoc.addNewSAMLAuthContext();
        AuthContextInfoType authCont = assertionInfo.addNewAuthContextInfo();
        IdAttributesType userAttrs = assertionInfo.addNewIdAttributes();
        //Set auth context attributes
        HashMap<String, String> ca = Enums.contextAttributes;
        String authContextRef = null, altAuthContextRef = null;
        for (List<String> cont : context) {
            String aid = cont.get(0);
            if (aid.equalsIgnoreCase("Shib-Identity-Provider")) {
                authCont.setIdentityProvider(cont.get(2));
            }
            if (aid.equalsIgnoreCase("Shib-Authentication-Instant")) {
                String ALT_DATE_TIME_FORMAT = "EEE MMM d HH:mm:ss zzz yyyy";
                SimpleDateFormat sdf = new SimpleDateFormat(ALT_DATE_TIME_FORMAT);
                Date issueInstant;
                try {
                    issueInstant = sdf.parse(cont.get(2));
                } catch (ParseException ex) {
                    issueInstant = new Date();
                }
                Calendar authInstant = Calendar.getInstance();
                authInstant.setTime(issueInstant);
                authCont.setAuthenticationInstant(authInstant);
            }
            if (aid.equalsIgnoreCase("Shib-AuthnContext-Class")) {
                authContextRef = cont.get(2);
            }
            if (aid.equalsIgnoreCase("Shib-AuthnContext-Decl")) {
                altAuthContextRef = cont.get(2);
            }
            if (aid.equalsIgnoreCase("Shib-Session-ID")) {
                authCont.setAssertionRef(cont.get(2));
            }
            if (aid.equalsIgnoreCase("Shib-Application-ID")) {
                authCont.setServiceID(cont.get(2));
            }
        }
        authCont.setAuthnContextClassRef(authContextRef == null ? altAuthContextRef : authContextRef);

        for (List<String> user : attribute) {
            String aid = user.get(0);
            try {
                String oid = Enums.idAttributes.get(aid);
                addSimpleAttribute(userAttrs, oid, aid, user.get(2));
            } catch (Exception ex) {
            }
        }

        return assertionInfoDoc;
    }

    private void addSimpleAttribute(IdAttributesType attrs, String oid, String name, String val) {
        String attrName = oid;
        if (oid != null && oid.length() > 0) {
            attrName = "urn:oid:" + oid;
        }
        AttributeMappingType idAttr = attrs.addNewAttributeMapping();
        AttributeType samlAttr = idAttr.addNewAttribute();
        XmlString attrVal = XmlString.Factory.newInstance();
        attrVal.setStringValue(val);
        XmlString[] valArray = new XmlString[]{attrVal};
        samlAttr.setAttributeValueArray(valArray);
        samlAttr.setFriendlyName(name);
        samlAttr.setName(attrName);
    }

    private AttributeType addAttribute(AttributeStatementType attributes, String id, String name, String val) {
        AttributeType attr = attributes.addNewAttribute();
        //        List<Object> attributeValue = attr.getAttributeValue();
        XmlObject attrVal = attr.addNewAttributeValue();
        attrVal.set(xmlString(val));
        attr.setName(id);
        attr.setFriendlyName(name);
        return attr;
    }

    private XmlString xmlString(String val) {
        XmlString xmlString = XmlString.Factory.newInstance();
        xmlString.setStringValue(val);
        return xmlString;
    }

    public AssertionDocument getAssertioinDocument(int idx) {
        return getAssertionFromBytes(assertions.get(idx));
    }
    
    public static AssertionDocument getAssertionFromBytes(byte[] assertionBytes){
        AssertionDocument assertion = null;
        try {
            assertion = AssertionDocument.Factory.parse(new ByteArrayInputStream(assertionBytes));
        } catch (Exception ex) {
        }
        return assertion;        
    }

    public List<List<String>> getAttribute() {
        return attribute;
    }

    public String getAuthType() {
        return authType;
    }

    public List<List<String>> getContext() {
        return context;
    }

    public String getId() {
        return id;
    }

    public String getIdAttribute() {
        return idAttribute;
    }

    public String getIdpEntityID() {
        return idpEntityID;
    }

    public String getRemoteUser() {
        return remoteUser;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public ArrayList<byte[]> getAssertions() {
        return assertions;
    }

    public void setAssertions(ArrayList<byte[]> assertions) {
        this.assertions = assertions;
    }
}
