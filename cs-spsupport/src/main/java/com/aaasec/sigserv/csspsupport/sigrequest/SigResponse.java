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
package com.aaasec.sigserv.csspsupport.sigrequest;

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.enums.Enums;
import com.aaasec.sigserv.cscommon.signature.SigVerifyResult;
import com.aaasec.sigserv.cscommon.xmldsig.XMLSign;
import com.aaasec.sigserv.csspapp.models.ServiceStatus;
import com.aaasec.sigserv.csspapp.models.SignSession;
import java.io.ByteArrayInputStream;
import java.util.Date;
import java.util.Map;
import org.apache.xmlbeans.XmlString;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignResponseExtensionType;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0CoreSchema.oasisNamesTcDss1.ResultDocument.Result;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument.SignResponse;

/**
 * Functions for handling sign responses.
 */
public class SigResponse implements Constants {

    private SigResponse() {
    }
    private static final String ENTITY_ID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

    public static ServiceStatus processSignResponse(byte[] sigResponse, Map<String, SignSession> sessionMap) {
        ServiceStatus status = new ServiceStatus();
        status.setResponseStatus();
        SignResponseDocument responseDoc = getResponseXmlObject(sigResponse);
        if (responseDoc == null) {
            status.setStatusCode(Enums.ResponseCodeMajor.SigCreationError);
            return status;
        }
        //Check if status was OK
        try {
            Result responseStatus = responseDoc.getSignResponse().getResult();
            String code = responseStatus.getResultMajor();
            if (!code.equals(Enums.ResponseCodeMajor.Success.getCode())) {
                status.responseCode = code;
                status.responseMessage = responseStatus.getResultMessage().getStringValue();
                return status;
            }
        } catch (Exception ex) {
        }

        SignSession session = getSignSession(responseDoc, sessionMap);
        if (session == null) {
            status.setStatusCode(Enums.ResponseCodeMajor.SigCreationError);
            return status;
        }
        status = session.getStatus();
        status.setResponseStatus();

        try {
            SigVerifyResult verifyResponse = XMLSign.verifySignature(sigResponse);
            session.setResponseSignatureValidity(verifyResponse);
            status.respSigValid = verifyResponse.valid;
            updateStatusAndSignedDoc(responseDoc, session);
        } catch (Exception ex) {
        }
        return status;

    }

    public static ServiceStatus processSignResponse(byte[] sigResponse, SignSession session) {
        ServiceStatus status = session.getStatus();
        status.setResponseStatus();

        try {
            SigVerifyResult verifyResponse = XMLSign.verifySignature(sigResponse);
            session.setResponseSignatureValidity(verifyResponse);
            status.respSigValid = verifyResponse.valid;

            SignResponseDocument responseDoc = SignResponseDocument.Factory.parse(new ByteArrayInputStream(sigResponse));
            updateStatusAndSignedDoc(responseDoc, session);

        } catch (Exception ex) {
        }
        return status;
    }

    public static SignResponseDocument getResponseXmlObject(byte[] sigResponse) {
        try {
            return SignResponseDocument.Factory.parse(new ByteArrayInputStream(sigResponse));
        } catch (Exception ex) {
            return null;
        }
    }

    public static SignSession getSignSession(SignResponseDocument responseDoc, Map<String, SignSession> sessionMap) {
        try {
            String requestId = responseDoc.getSignResponse().getRequestID();
            if (sessionMap.containsKey(requestId)) {
                return sessionMap.get(requestId);
            }
        } catch (Exception ex) {
        }
        return null;
    }

    public static void updateStatusAndSignedDoc(SignResponseDocument responseDoc, SignSession session) {
        ServiceStatus status = session.getStatus();

        try {
            SignResponse response = responseDoc.getSignResponse();
            SignResponseExtensionType eid2Response = response.getOptionalOutputs().getSignResponseExtension();
            String responseNonce = response.getRequestID();
            status.signTaskID = responseNonce;
            session.setSignedDoc(null);
            session.setSignedPresentationDocument(new byte[]{});
            session.setSigResponse(responseDoc);
            session.setSignedDocValidity(null);
            session.setSigRequest(eid2Response.getRequest());

//            SignatureInfo signInfo = session.getSignInfo();
            String requestNonce = session.getSignRequestID();

            Result responseStatus = responseDoc.getSignResponse().getResult();
            String statusCode = responseStatus.getResultMajor();
            status.responseCode = statusCode;
            String statusString = responseStatus.getResultMessage().getStringValue();
            status.responseMessage = statusString;
            byte[] signatureValue;
            byte[] tbsBytes=null;
            try {
                signatureValue = response.getSignatureObject().getOther().getSignTasks().getSignTaskDataArray(0).getBase64Signature().getByteArrayValue();
                tbsBytes = response.getSignatureObject().getOther().getSignTasks().getSignTaskDataArray(0).getToBeSignedBytes();
                
            } catch (Exception ex) {
                signatureValue = response.getSignatureObject().getBase64Signature().getByteArrayValue();
            }
            byte[][] responseCertChain = eid2Response.getSignatureCertificateChain().getX509CertificateArray();
            Date sigTime = eid2Response.getResponseTime().getTime();
            status.signingTime = TIME_FORMAT.format(sigTime);

            if (!(requestNonce.equals(responseNonce) && statusCode.equals(Enums.ResponseCodeMajor.Success.getCode()))) {
                return;
            }
            
            
            session.completeSignedDocument(signatureValue, responseCertChain, tbsBytes);


            status.pathLen = responseCertChain.length;

            status.signedDocValid = session.getSignedDocValidity().valid;

            // If response processing reached this point, then set response valid status
            status.validResponse = (status.respSigValid && status.signedDocValid);
            getUserId(eid2Response, status);

        } catch (Exception ex) {
        }
    }

    public static void getUserId(SignResponseExtensionType response, ServiceStatus status) {
        status.userId.clear();
        try {
            AttributeType[] respIdAttrs = response.getSignerAssertionInfo().getAttributeStatement().getAttributeArray();
            for (AttributeType respAttr : respIdAttrs) {
                String friendlyName = respAttr.getFriendlyName();
                String val = ((XmlString) respAttr.getAttributeValueArray(0)).getStringValue();
                status.addUserAttr(friendlyName, val);
            }
        } catch (Exception ex) {
        }
    }
}
