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
package com.aaasec.sigserv.csspsupport.testcases;

import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.xmldsig.XMLSign;
import com.aaasec.sigserv.csspapp.models.SignSession;
import com.aaasec.sigserv.csspsupport.models.SupportModel;
import com.aaasec.sigserv.csspsupport.sigrequest.SigRequest;
import java.util.Calendar;
import org.w3c.dom.Node;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignRequestExtensionType;
import x0CoreSchema.oasisNamesTcDss1.Eid2ReqAnyType;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument.SignRequest;

/**
 * Functions for handling test cases.
 */
public class TestRequests {

    public static byte[] getTestCaseRequest(SupportModel model, SignSession session, String testId) {
        SignRequestDocument sigRequestDoc = SignRequestDocument.Factory.newInstance();
        SignRequest sigRequest = sigRequestDoc.addNewSignRequest();
        //Set the request values
        SigRequest.getRequestData(sigRequest, model, session);
        //Get the eid2 request extension
        SignRequestExtensionType eid2Request = sigRequest.getOptionalInputs().getSignRequestExtension();
        // Generate unsigned request XML with marshaller
        Calendar cal = Calendar.getInstance();
        if (testId.equals("oldReq")) {
            long oldTime = System.currentTimeMillis() - 1000 * 60 * 60 * 24;
            cal.setTimeInMillis(oldTime);
            eid2Request.setRequestTime(cal);
        }
        if (testId.equals("predatedReq")) {
            long futureTime = System.currentTimeMillis() + 1000 * 60 * 60 * 24;
            cal.setTimeInMillis(futureTime);
            eid2Request.setRequestTime(cal);
        }
        Node sigParent = getRequestSignatureParent(sigRequest);
        byte[] unsignedReqXML = XmlBeansUtil.getStyledBytes(sigRequestDoc);
        // Sign request
        byte[] signedReqXML;
        signedReqXML = XMLSign.getSignedXML(unsignedReqXML, model.getPrivateKey(), model.getCert(),sigParent).sigDocBytes;

        if (testId.equals("badReqSig")) {
            signedReqXML = XMLSign.getSignedXML(unsignedReqXML, model.getTestPrivateKey(), model.getCert(),sigParent).sigDocBytes;
        }
        if (testId.equals("unknownRequester")) {
            signedReqXML = XMLSign.getSignedXML(unsignedReqXML, model.getTestPrivateKey(), model.getTestCert(),sigParent).sigDocBytes;
        }
        
//        String sReqText = new String(signedReqXML,Charset.forName("UTF-8"));

        return signedReqXML;

    }

    private static Node getRequestSignatureParent(SignRequest sigReq) {
        Eid2ReqAnyType optionalInputs = sigReq.getOptionalInputs();
        if (optionalInputs == null) {
            optionalInputs = sigReq.addNewOptionalInputs();
        }
        return optionalInputs.getDomNode();
    }
}
