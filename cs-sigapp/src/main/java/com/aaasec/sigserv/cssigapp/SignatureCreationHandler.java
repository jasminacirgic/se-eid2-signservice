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
package com.aaasec.sigserv.cssigapp;

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.SigAlgorithms;
import com.aaasec.sigserv.cscommon.XhtmlForm;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.cscommon.enums.Enums;
import com.aaasec.sigserv.cscommon.enums.Enums.ResponseCodeMajor;
import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.testdata.TestData;
import com.aaasec.sigserv.cscommon.xmldsig.EcdsaSigValue;
import com.aaasec.sigserv.cscommon.xmldsig.XMLSign;
import com.aaasec.sigserv.cssigapp.ca.CAFactory;
import com.aaasec.sigserv.cssigapp.ca.CertificationAuthority;
import com.aaasec.sigserv.cssigapp.data.DbSignTask;
import com.aaasec.sigserv.cssigapp.data.SigConfig;
import com.aaasec.sigserv.cssigapp.db.SignTaskTable;
import com.aaasec.sigserv.cssigapp.models.SigServerModel;
import com.aaasec.sigserv.cssigapp.utils.ASN1Util;
import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import iaik.x509.X509Certificate;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;
import org.w3c.dom.Node;
import se.elegnamnden.id.csig.x10.dssExt.ns.Base64SignatureType;
import se.elegnamnden.id.csig.x10.dssExt.ns.CertificateChainType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SAMLAssertionsType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignRequestExtensionType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignResponseExtensionType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignTaskDataType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignTaskDataType.SigType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignerAssertionInfoType;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0Assertion.oasisNamesTcSAML2.ConditionsType;
import x0CoreSchema.oasisNamesTcDss1.Base64SignatureDocument;
import x0CoreSchema.oasisNamesTcDss1.Eid2RespAnyType;
import x0CoreSchema.oasisNamesTcDss1.Eid2SigTaskObjAnyType;
import x0CoreSchema.oasisNamesTcDss1.InternationalStringType;
import x0CoreSchema.oasisNamesTcDss1.ResultDocument.Result;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument.SignRequest;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument.SignResponse;

/**
 * Signature creation handler.
 */
public class SignatureCreationHandler implements Constants {

    private static final Logger LOG = Logger.getLogger(SignatureCreationHandler.class.getName());
    private static final String URN_PREFIX = "urn:oid:";
    private SigServerModel model;
    private String caDir, caMainDir;
    private CertificationAuthority ca;
    private CAFactory caFactory = new CAFactory();
    private KeyStoreFactory ksFactory;
    private SignTaskTable signDb;

    public SignatureCreationHandler(SigServerModel model) {
        this.model = model;
        ksFactory = new KeyStoreFactory(model);
        ksFactory.cleanup();
        ksFactory.stackUp();
        caMainDir = FileOps.getfileNameString(model.getDataLocation(), "CA");
        String sigTaskDir = FileOps.getfileNameString(model.getDataLocation(), "sigTasks");
        String sigTaskDbFile = FileOps.getfileNameString(sigTaskDir, "sigTasks.db");
        signDb = new SignTaskTable(sigTaskDbFile);
        getCA();
    }

    private CertificationAuthority getCA() {
        SigConfig conf = model.reloadConf();
        caDir = FileOps.getfileNameString(caMainDir, conf.getSignatureCaName());
        ca = new CertificationAuthority(conf.getSignatureCaName(), caDir, model);
        if (!ca.isInitialized()) {
            caFactory.createCa(ca);
        }
        return ca;
    }

    public String createSignature(String sigTaskId, AuthData user) {

        //Check if sigTask is serviced
        DbSignTask signTask = signDb.getDbRecord(sigTaskId);
        if (signTask == null || signTask.getServiced() > 0) {
            return "Signature service error - Signing task is missing or has already ben serviced";
        }
        signTask.setServiced(System.currentTimeMillis());
        signDb.addOrReplaceRecord(signTask);

        // Process task
        ca = getCA();
        RequestAndResponse reqRes = getSignatureResponse(sigTaskId, user);
        SignResponseDocument responseDoc = reqRes.getReponseDoc();

        //Sign response
        try {
            String responseUrl = getResponseUrl(reqRes.getRequest());

            String nonce = reqRes.getRequest().getRequestID();
            Node sigParent = getResponseSignatureParent(responseDoc);
            byte[] unsignedXml = XmlBeansUtil.getStyledBytes(responseDoc);
            byte[] signedResponse = ca.signResponse(unsignedXml, sigParent);
            String xhtml = XhtmlForm.getSignXhtmlForm(XhtmlForm.Type.SIG_RESPONSE_FORM, responseUrl, signedResponse, nonce);
            
            //Store testdata
            TestData.storeXhtmlResponse(nonce, xhtml);
            TestData.storeResponse(nonce,signedResponse);
            
            return xhtml;
        } catch (Exception ex) {
        }
        return "Signature service error - Unable to service the request";
    }

    public RequestAndResponse getSignatureResponse(String sigTaskId, AuthData user) {
        RequestAndResponse reqRes = new RequestAndResponse();

        ksFactory.stackUp();
        DbSignTask signTask = signDb.getDbRecord(sigTaskId);
        if (signTask == null) {
            reqRes.setReponseDoc(getErrorResponse(null, null, ResponseCodeMajor.SigCreationError, "No matching request"));
            return reqRes;
        }
        byte[] requestBytes = signTask.getRequest();
        SignRequestDocument sigReqDoc = null;
        SignRequest sigReq = null;
        SignRequestExtensionType eid2Req = null;
        try {
            sigReqDoc = SignRequestDocument.Factory.parse(new ByteArrayInputStream(requestBytes));
            sigReq = sigReqDoc.getSignRequest();
            eid2Req = sigReq.getOptionalInputs().getSignRequestExtension();
        } catch (Exception ex) {
        }
        if (eid2Req == null) {
            reqRes.setReponseDoc(getErrorResponse(null, null, ResponseCodeMajor.InsufficientInfo));
            return reqRes;
        }
        reqRes.setRequestDoc(sigReqDoc);
        byte[] encSigReq = requestBytes;

        boolean userMatch = checkUserID(eid2Req, user);
        if (!userMatch) {
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.BadRequest, "Authenticated user does not match the requested signer"));
            return reqRes;
        }
        ConditionsType conditions = eid2Req.getConditions();
        boolean inValidityTime = getTimeValidity(conditions);
        if (!inValidityTime) {
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.BadRequest, "Request has expired"));
            return reqRes;
        }

        try {
            //Get requested sig algo
            String reqSigAlgoURI = eid2Req.getRequestedSignatureAlgorithm();
            SigAlgorithms sigAlgo = SigAlgorithms.getAlgoByURI(reqSigAlgoURI);
            //Check CMS signed attributes
            byte[] tDataBytes = null;
            SigType.Enum sigType = null;
            Eid2SigTaskObjAnyType[] otherArray = sigReq.getInputDocuments().getOtherArray();
            for (Eid2SigTaskObjAnyType otherDocInp : otherArray) {
                SignTaskDataType sigInfoInp = otherDocInp.getSignTasks().getSignTaskDataArray(0);
                if (sigInfoInp != null) {
                    tDataBytes = sigInfoInp.getToBeSignedBytes();
                    sigType = sigInfoInp.getSigType();
                    break;
                }
            }
            if (sigType == SigType.CMS || sigType == SigType.PDF) {
                //Check signing time
                Date cmsSigningTime = ASN1Util.getCmsSigningTime(tDataBytes);
                // If no time is available
                if (cmsSigningTime == null) {
                    reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError));
                    return reqRes;
                }
                long claimedTime = cmsSigningTime.getTime();
                long currentTime = System.currentTimeMillis();
                // check that claimed signing time is within tolerances
                if (claimedTime < (currentTime - MAX_SIG_TIME_TOLERANCE) || claimedTime > currentTime + MAX_SIG_TIME_TOLERANCE) {
                    reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError));
                    return reqRes;
                }
            }

            KeyPair kp = ksFactory.getKeyPair(sigAlgo, sigReq.getRequestID());

            //Issue signing cert
            X509Certificate userCert = ca.issueUserCert(user, kp.getPublic(), eid2Req.getCertRequestProperties());
            
            //Store cert TestData
            TestData.storeUserCert(sigReq.getRequestID(), userCert.getEncoded());
            
            if (userCert == null) {
                reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError, "Failed to issue signer certificate"));
                LOG.warning("Certificate issueance prohibited due to unsatisfied attribute requirements");
                return reqRes;
            }
            X509Certificate[] chain = ca.getChain(userCert);

            //Create signature
            byte[] signature = new byte[]{};
            byte[] tbsData = getToBeSignedData(sigAlgo, tDataBytes);
            switch (sigAlgo) {
                case RSA:
                    signature = XMLSign.rsaSign(tbsData, kp.getPrivate());
                    break;
                case ECDSA:
                    EcdsaSigValue ecdsaSigvalue = XMLSign.ecdsaSignDataWithSha256(tbsData, kp.getPrivate());
                    signature = ecdsaSigvalue.toByteArray(256);
            }
//            byte[] signature = XMLSign.rsaSign(tbsData, ksObjects.getPk());
            try {
                reqRes.setReponseDoc(generateSignResponse(encSigReq, sigReq, user, chain, signature, sigAlgo.getSigAlgo()));
            } catch (Exception ex) {
                reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError));

            }

        } catch (Exception ex) {
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError));
            LOG.log(Level.WARNING, null, ex);
        }
        return reqRes;
    }

    private boolean checkUserID(SignRequestExtensionType sigReq, AuthData user) {
        boolean match = true;
        AttributeType[] signerAttrs;
        try {
            signerAttrs = sigReq.getSigner().getAttributeArray();
        } catch (Exception ex) {
            return false;
        }

        List<List<String>> idpAttributes = user.getAttribute();
        for (AttributeType signerAttr : signerAttrs) {
            String attrId = signerAttr.getName();
            String attrVal;
            XmlObject[] aa = signerAttr.getAttributeValueArray();
            if (aa[0] instanceof XmlString) {
                attrVal = ((XmlString) aa[0]).getStringValue();
            } else {
                return false;
            }
            // check if attribute is provided by idp
            boolean attrMatch = false;
            for (List<String> valueList : idpAttributes) {
                String attrName = valueList.get(0);
                if (Enums.idAttributes.containsKey(attrName)) {
                    if (Enums.idAttributes.get(attrName).equals(stripOid(attrId))) {
                        if (valueList.get(2).equals(attrVal)) {
                            attrMatch = true;
                            break;
                        }
                    }
                }
            }
            if (!attrMatch) {
                match = false;
                break;
            }
        }

        return match;
    }

    private static String stripOid(String oid) {
        String norm = (oid.startsWith("urn:oid:")) ? oid.substring(8) : oid;
        return norm;

    }

    private static boolean compareOidStrings(String oid1, String oid2) {
        String norm1 = stripOid(oid1);
        String norm2 = stripOid(oid2);
        return norm1.equalsIgnoreCase(norm2);
    }

    private String stripUrn(String typeId) {
        if (typeId.startsWith(URN_PREFIX)) {
            return typeId.substring(URN_PREFIX.length());
        }
        return typeId;
    }

    private SignResponseDocument generateSignResponse(byte[] encSigReq, SignRequest sigReq,
            AuthData user, X509Certificate[] chain, byte[] signature, String sigAlgo) throws CertificateEncodingException {
        SignRequestExtensionType eid2Req = sigReq.getOptionalInputs().getSignRequestExtension();
        SignResponseDocument responseDoc = SignResponseDocument.Factory.newInstance();
        SignResponse response = responseDoc.addNewSignResponse();
        SignResponseExtensionType eid2Response = response.addNewOptionalOutputs().addNewSignResponseExtension();
        eid2Response.setVersion(EID2_PROTOCOL_VERSION);

        Result result = response.addNewResult();
        InternationalStringType resultMessage = result.addNewResultMessage();
        resultMessage.setLang("en");
        resultMessage.setStringValue(Enums.ResponseCodeMajor.Success.getMessage());
        result.setResultMajor(Enums.ResponseCodeMajor.Success.getCode());

        CertificateChainType certChainType = eid2Response.addNewSignatureCertificateChain();
        for (X509Certificate cert : chain) {
            certChainType.addNewX509Certificate().setByteArrayValue(cert.getEncoded());
        }
        // Add signature result
        try {
            SignTaskDataType signatureTaskData = sigReq.getInputDocuments().getOtherArray(0).getSignTasks().getSignTaskDataArray(0);            
            SignTaskDataType respSigTaskData = SignTaskDataType.Factory.parse(signatureTaskData.getDomNode());
            Base64SignatureType b64Signature = respSigTaskData.addNewBase64Signature();
            b64Signature.setByteArrayValue(signature);
            b64Signature.setType(sigAlgo);
            response.addNewSignatureObject().addNewOther().addNewSignTasks().setSignTaskDataArray(new SignTaskDataType[]{respSigTaskData});
        } catch (Exception ex) {
            // If no signature task object was present in the request
            Base64SignatureDocument.Base64Signature base64Signature = response.addNewSignatureObject().addNewBase64Signature();
            base64Signature.setByteArrayValue(signature);
            base64Signature.setType(sigAlgo);
        }


        response.setProfile(sigReq.getProfile());
        response.setRequestID(sigReq.getRequestID());
        eid2Response.setResponseTime(Calendar.getInstance());
        eid2Response.setRequest(encSigReq);
        eid2Response.setSignerAssertionInfo(user.getUserAssertion());
        SignerAssertionInfoType signerAssertionInfo = eid2Response.getSignerAssertionInfo();
        List<byte[]> assertions = user.getAssertions();
        if (!assertions.isEmpty()) {
            
            //Store Assertion in TestData
            TestData.storeAssertions(sigReq.getRequestID(), assertions);
            
            SAMLAssertionsType SamlAssertions = signerAssertionInfo.addNewSamlAssertions();
            byte[][] assertionArray = assertions.toArray(new byte[][]{});
            SamlAssertions.setAssertionArray(assertionArray);
        }

        return responseDoc;
    }

    private SignResponseDocument getErrorResponse(byte[] encSigReq, SignRequest sigReq, ResponseCodeMajor responseCode) {
        return getErrorResponse(encSigReq, sigReq, responseCode, responseCode.getMessage());
    }

    private SignResponseDocument getErrorResponse(byte[] encSigReq, SignRequest sigReq, ResponseCodeMajor responseCode, String message) {
        SignResponseDocument responseDoc = SignResponseDocument.Factory.newInstance();
        SignResponse response = responseDoc.addNewSignResponse();
        SignResponseExtensionType eid2Response = response.addNewOptionalOutputs().addNewSignResponseExtension();
        eid2Response.setVersion(EID2_PROTOCOL_VERSION);
        if (encSigReq != null && sigReq != null) {
            eid2Response.setRequest(encSigReq);
            response.setRequestID(sigReq.getRequestID());
        }
        Result result = response.addNewResult();
        InternationalStringType resultMessage = result.addNewResultMessage();
        resultMessage.setLang("en");
        resultMessage.setStringValue(message);
        result.setResultMajor(responseCode.getCode());

        return responseDoc;
    }

    private Node getResponseSignatureParent(SignResponseDocument sigResponseDoc) {
        SignResponse signResponse = sigResponseDoc.getSignResponse();
        if (signResponse == null) {
            sigResponseDoc.addNewSignResponse();
        }
        Eid2RespAnyType optionalOutputs = signResponse.getOptionalOutputs();
        if (optionalOutputs == null) {
            optionalOutputs = signResponse.addNewOptionalOutputs();
        }
        return optionalOutputs.getDomNode();
    }

    private String getTestPrint(byte[] xmlBytes, SignResponseExtensionType response) {
        // Test print 
        StringBuilder b = new StringBuilder();
        b.append(new String(xmlBytes, Charset.forName("UTF-8"))).append("\n");
        try {
            byte[][] signatureCertificates = response.getSignatureCertificateChain().getX509CertificateArray();
            for (byte[] b64Cert : signatureCertificates) {
                X509Certificate cert = CertificateUtils.getCertificate(b64Cert);
                if (cert != null) {
                    b.append(cert.toString(true)).append("\n");
                }
            }
        } catch (Exception ex) {
        }

        return b.toString();

    }

    private boolean getTimeValidity(ConditionsType conditions) {
        boolean valid = false;
        try {
            long present = System.currentTimeMillis();
            long notBefore = conditions.getNotBefore().getTime().getTime();
            long notAfter = conditions.getNotOnOrAfter().getTime().getTime();

            valid = (notBefore < present && present < notAfter);
        } catch (Exception ex) {
        }

        return valid;
    }

    private String getResponseUrl(SignRequest request) {
        try {
            ConditionsType conditions = request.getOptionalInputs().getSignRequestExtension().getConditions();
            return conditions.getAudienceRestrictionArray(0).getAudienceArray(0);
        } catch (Exception ex) {
        }
        return null;
    }

    private byte[] getToBeSignedData(SigAlgorithms sigAlgo, byte[] tDataBytes) {
        switch (sigAlgo) {
            case ECDSA:
                return tDataBytes;
        }

        // If RSA
        byte[] tbsData = null;
        byte[] hash;
        byte[] pkcs1;

        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(sigAlgo.getMessageDigestName());
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SignatureCreationHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        md.update(tDataBytes);
        hash = md.digest();
        pkcs1 = pkcs1 = sigAlgo.getPKCS1hash(hash);

        return pkcs1;
    }

    class RequestAndResponse {

        private SignRequestDocument requestDoc;
        private SignResponseDocument responseDoc;

        public RequestAndResponse() {
        }

        public RequestAndResponse(SignRequestDocument request, SignResponseDocument reponse) {
            this.requestDoc = request;
            this.responseDoc = reponse;
        }

        public RequestAndResponse(SignRequestDocument request) {
            this.requestDoc = request;
        }

        public RequestAndResponse(SignResponseDocument reponse) {
            this.responseDoc = reponse;
        }

        public SignResponseDocument getReponseDoc() {
            return responseDoc;
        }

        public void setReponseDoc(SignResponseDocument reponseDoc) {
            this.responseDoc = reponseDoc;
        }

        public SignRequestDocument getRequestDoc() {
            return requestDoc;
        }

        public void setRequestDoc(SignRequestDocument requestDoc) {
            this.requestDoc = requestDoc;
        }

        public SignRequest getRequest() {
            if (requestDoc == null) {
                return null;
            }
            return requestDoc.getSignRequest();
        }

        public SignResponse getResponse() {
            if (responseDoc == null) {
                return null;
            }
            return responseDoc.getSignResponse();
        }
    }
}
