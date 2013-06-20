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
package com.aaasec.sigserv.csspserver.test;

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.PEM;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import com.aaasec.sigserv.csspserver.models.RequestModel;
import com.aaasec.sigserv.csspserver.models.SpSession;
import com.aaasec.sigserv.csspserver.utility.SigRequestMessage;
import com.aaasec.sigserv.csspserver.utility.SpServerLogic;
import com.aaasec.sigserv.csspsupport.CertType;
import com.aaasec.sigserv.csspsupport.Property;
import com.aaasec.sigserv.csspsupport.SignRequestParams;
import com.aaasec.sigserv.csspsupport.SignTaskParams;
import com.aaasec.sigserv.csspsupport.SignerAuthLoa;
import com.aaasec.sigserv.csspsupport.SpSupportWs;
import com.aaasec.sigserv.csspsupport.SpSupportWs_Service;
import com.aaasec.sigserv.csspsupport.VerifyResponse;
import iaik.x509.X509Certificate;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.security.cert.CertificateFactory;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import x0Assertion.oasisNamesTcSAML2.AssertionDocument;
import x0Assertion.oasisNamesTcSAML2.AssertionType;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument.SignRequest;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument;

/**
 * Functions for test cases.
 */
public class TestCases {

    private TestCases() {
    }

    public static String prepareTestRedirect(HttpServletRequest request,
            HttpServletResponse response, RequestModel req, boolean addSignMessage) {

        SpSession session = req.getSession();
        String xhtml;
        String nonce = "";
        String testCaseName = req.getId();
        if (session.getSigRequest() == null) {
            return "No request <a href='index.jsp'>back</a>";
        }
        if (addSignMessage) {
            session.setSignMessage(SigRequestMessage.getMessage(req));
        } else {
            session.setSignMessage(null);
        }

        try { // Call Web Service Operation
            SpSupportWs_Service service = new SpSupportWs_Service();
            SpSupportWs port = service.getSpSupportWsPort();
            // Initialize WS operation arguments
            SignRequestParams signRequestParams = new SignRequestParams();

            signRequestParams.setCertType(CertType.PKC);
            signRequestParams.setLoa(SignerAuthLoa.LOA_3);
            signRequestParams.setIdpEntityId(session.getIdpEntityId());
            signRequestParams.setSignerIdAttr(session.getSignerAttribute());
            signRequestParams.setSignerId(session.getSignerId());
            SpServerLogic.setProperty(signRequestParams, Property.REQUESTED_ALGORITHM, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
            if (session.getSignMessage() != null) {
                SpServerLogic.setProperty(signRequestParams, Property.SIGN_MESSAGE, new String(session.getSignMessage(), Charset.forName("UTF-8")));
            }
            //setOptionalProperty(signRequestParams, Property.RETURN_URL, returnUrl);

            List<SignTaskParams> sigTaskParams = signRequestParams.getSignTaskParams();
            SignTaskParams stp = new SignTaskParams();
            sigTaskParams.add(stp);
            //stp.setSigType(SigType.XML);
            //stp.setAdesType(AdesType.NONE);
            stp.setTbsDocument(session.getDocument());

            //Set test case parameters
            setSigReqParameter(signRequestParams, "testcase", testCaseName);
            setSigReqParameter(signRequestParams, "testcaseRef", session.getSignRequestID());

            // process result
            com.aaasec.sigserv.csspsupport.SignRequestXhtml result = port.signRequest(signRequestParams);
            xhtml = new String(result.getSignRequestXhtml(), Charset.forName("UTF-8"));

            return xhtml;

        } catch (Exception ex) {
            return "Failed to generate sign request";
        }
    }

    public static void setSigReqParameter(SignRequestParams signRequestParams, String extProperty, String value) {
        SignRequestParams.Parameters ext = signRequestParams.getParameters();
        if (ext == null) {
            ext = new SignRequestParams.Parameters();
            signRequestParams.setParameters(ext);
        }
        List<SignRequestParams.Parameters.Entry> entryList = ext.getEntry();
        SignRequestParams.Parameters.Entry entry = new SignRequestParams.Parameters.Entry();
        entry.setKey(extProperty);
        entry.setValue(value);
        entryList.add(entry);
    }


    public static byte[] getRawData(RequestModel req) {
        SpSession session = req.getSession();
        String id = req.getId();
        String message = "";
        if (req.getId().equalsIgnoreCase("request")) {
            return session.getSigRequest();
        }
        if (req.getId().equalsIgnoreCase("response")) {
            SignResponseDocument sigResponse = session.getSigResponse();
            return XmlBeansUtil.getBytes(sigResponse);
        }
        if (req.getId().equalsIgnoreCase("assertion")) {
            SignResponseDocument sigResponse = session.getSigResponse();
            try {
                AssertionType assertion = AuthData.getAssertionFromBytes(
                        sigResponse.getSignResponse().getOptionalOutputs().getSignResponseExtension().getSignerAssertionInfo().getSamlAssertions().getAssertionArray(0)).getAssertion();
//                AssertionType assertion = sigResponse.getSignResponse().getOptionalOutputs().getSignResponseExtension().getSignerAssertionInfo().getSamlAssertions().getAssertionArray(0);
                AssertionDocument assertionDoc = AssertionDocument.Factory.newInstance();
                assertionDoc.setAssertion(assertion);
                return XmlBeansUtil.getBytes(assertionDoc);
            } catch (Exception ex) {
                message = "<Error>No assertion data</Error>";
                return message.getBytes(Charset.forName("UTF-8"));
            }

        }
        message = "<Error>No data</Error>";
        return message.getBytes(Charset.forName("UTF-8"));

    }

    public static String getTestData(RequestModel req) {
        SpSession session = req.getSession();
        String id = req.getId();
        String parameter = req.getParameter();

        try {
            if (id.equals("document")) {
                return xmp(new String(session.getDocument(), Charset.forName("UTF-8")));
            }

            if (req.getAction().equals("verify")) {
                byte[] sigDoc;
                switch (session.getDocumentType()) {
                    case XML:
                        sigDoc = session.getSignedDoc();
                        break;
                    default:
                        sigDoc = FileOps.readBinaryFile(session.getSigFile());
                }


                try { // Call Web Service Operation
                    SpSupportWs_Service service = new SpSupportWs_Service();
                    SpSupportWs port = service.getSpSupportWsPort();
                    VerifyResponse verifyResponse = port.verifySignature(sigDoc, null, null);
                    byte[] verifyReport = verifyResponse.getVerifyReport();
                    return new String(verifyReport, Charset.forName("UTF-8"));
                } catch (Exception ex) {
                    return "No Data";
                }
            }
//            if (req.getAction().equals("verify")) {
//                InputStream sigDocIs;
//                switch (session.getDocumentType()) {
//                    case XML:
//                        sigDocIs = new ByteArrayInputStream(session.getSignedDoc());
//                        break;
//                    default:
//                        sigDocIs = new FileInputStream(session.getSigFile());
//                }
//                
//                
//                return SignSupportAPI.getValidationReport(sigDocIs);
//            }
            if (id.equals("formSigDoc")) {
                return xmp(new String(session.getSignedPresentationDocument(), Charset.forName("UTF-8")));
            }

            if (id.equals("signedDoc")) {
                return xmp(new String(session.getSignedDoc(), Charset.forName("UTF-8")));
            }
            if (id.equals("request")) {
                return xmp(getFormattedRequest(session));
            }
            if (id.equals("response")) {
                return xmp(getFormattedResponse(session));
            }
            if (id.equals("certificate")) {
                int idx = getInt(req.getParameter());
                byte[][] signatureCertificate = session.getSigResponse().getSignResponse().getOptionalOutputs()
                        .getSignResponseExtension().getSignatureCertificateChain().getX509CertificateArray();
                byte[] certB64 = signatureCertificate[idx];
                return xmp(getCertPrint(certB64) + "\n\n"
                        + PEM.getPemCert(certB64));
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return "No data";
    }

    public static String getFormattedResponse(SpSession session) {
        SignResponseDocument sigResponseDoc = session.getSigResponse();
        byte[] xML = XmlBeansUtil.getStyledBytes(sigResponseDoc);
        return new String(xML, Charset.forName("UTF-8"));
    }

    public static String getFormattedRequest(SpSession session) {
        try {
            SignRequestDocument sigRequestDoc = SignRequestDocument.Factory.parse(new ByteArrayInputStream(session.getSigRequest()));
            SignRequest sigRequest = sigRequestDoc.getSignRequest();
            byte[] xML = XmlBeansUtil.getStyledBytes(sigRequestDoc);
            return new String(xML, Charset.forName("UTF-8"));
        } catch (Exception ex) {
            return "No Data";
        }
    }

    public static iaik.x509.X509Certificate getIaikCert(byte[] certBytes) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "IAIK");
            X509Certificate iaikCert = (iaik.x509.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            return iaikCert;
        } catch (Exception ex) {
        }
        return null;
    }

    private static String getCertPrint(byte[] certBytes) {
        X509Certificate cert = getIaikCert(certBytes);
        return cert == null ? "No Data" : cert.toString(true);
    }

    /**
     * Gets the integer representation of an input string.
     *
     * @param intString input string
     * @return integer representation of the input string, returns 0 of the
     * string is not a legitimate integer string.
     */
    private static int getInt(String intString) {
        int val = 0;
        try {
            val = Integer.parseInt(intString);
        } catch (Exception ex) {
        }
        return val;
    }

    private static String xmp(String data) {
        return "<xmp>" + data + "</xmp>";
    }
}
