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
package com.aaasec.sigserv.csspsupport;

import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.XhtmlForm;
import com.aaasec.sigserv.cscommon.enums.Enums;
import static com.aaasec.sigserv.cscommon.enums.SigDocumentType.PDF;
import static com.aaasec.sigserv.cscommon.enums.SigDocumentType.XML;
import com.aaasec.sigserv.cscommon.enums.SpsStatusGroup;
import com.aaasec.sigserv.cscommon.enums.SpsStatus;
import com.aaasec.sigserv.csspapp.SignSupportAPI;
import com.aaasec.sigserv.csspapp.models.IdAttribute;
import com.aaasec.sigserv.csspapp.models.ServiceStatus;
import com.aaasec.sigserv.csspapp.models.SignSession;
import com.aaasec.sigserv.csspsupport.context.SpSuppContextParams;
import com.aaasec.sigserv.csspsupport.models.SupportConfig;
import com.aaasec.sigserv.csspsupport.models.SupportModel;
import com.aaasec.sigserv.csspsupport.signtask.SigSessionFactory;
import com.aaasec.sigserv.csspsupport.sigrequest.SigRequest;
import com.aaasec.sigserv.csspsupport.sigrequest.SigResponse;
import com.aaasec.sigserv.csspsupport.testcases.TestRequests;
import com.aaasec.sigserv.csspsupport.wsdto.CertType;
import com.aaasec.sigserv.csspsupport.wsdto.SignRequestParams;
import com.aaasec.sigserv.csspsupport.wsdto.SignRequestXhtml;
import com.aaasec.sigserv.csspsupport.wsdto.SignTaskParams;
import com.aaasec.sigserv.csspsupport.wsdto.SignTaskResult;
import com.aaasec.sigserv.csspsupport.wsdto.SignatureResult;
import com.aaasec.sigserv.csspsupport.wsdto.SignerAuthLoa;
import static com.aaasec.sigserv.csspsupport.wsdto.SignerAuthLoa.loa1;
import static com.aaasec.sigserv.csspsupport.wsdto.SignerAuthLoa.loa2;
import static com.aaasec.sigserv.csspsupport.wsdto.SignerAuthLoa.loa3;
import static com.aaasec.sigserv.csspsupport.wsdto.SignerAuthLoa.loa4;
import com.aaasec.sigserv.csspsupport.wsdto.Status;
import com.aaasec.sigserv.csspsupport.wsdto.VerifyResponse;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.jws.WebService;
import javax.jws.WebMethod;
import javax.jws.WebParam;

/**
 * Web service API
 */
@WebService(serviceName = "SpSupportWs")
public class SpSupportWs {

    /**
     * Web service operation
     */
    @WebMethod(operationName = "signRequest")
    public SignRequestXhtml signRequest(@WebParam(name = "signRequestParams") SignRequestParams signRequestParams) {
        return getSignRequestXhtml(signRequestParams);
    }

    /**
     * Web service operation
     */
    @WebMethod(operationName = "completeSigning")
    public SignatureResult completeSigning(@WebParam(name = "signResponse") byte[] signResponse) {
        return getSignatureResult(signResponse);
    }

    /**
     * Web service operation
     */
    @WebMethod(operationName = "verifySignature")
    public VerifyResponse verifySignature(@WebParam(name = "signedDocument") byte[] signedDoc, @WebParam(name = "validationPolicy") String trustPolicy, @WebParam(name = "parameters") Map<String, String> parameters) {
        return getSignatureValidationReport(signedDoc, trustPolicy, parameters);
    }

    private SignRequestXhtml getSignRequestXhtml(SignRequestParams srp) {
        try {
            SupportConfig conf = SpSuppContextParams.getConf();
            String sigTempDir = SpSuppContextParams.getSigTempDir();
            Map<String, SignSession> signTaskMap = SpSuppContextParams.getSignTaskMap();
            List<SignTaskParams> sigTaskRequests = srp.getSignTaskParams();
            if (sigTaskRequests == null || sigTaskRequests.isEmpty()) {
                return getReqStatusResponse(SpsStatusGroup.SigRequest, SpsStatus.NoSignTask);
            }

            SignTaskParams stp = sigTaskRequests.get(0);
            Map<SignRequestParams.Property, String> optionalProperties = srp.getProperties();

            byte[] docBytes = stp.getTbsDocument();
            byte[] signMessBytes = getSigReqProperty(SignRequestParams.Property.signMessage, optionalProperties).getBytes(Charset.forName("UTF-8"));
            cleanupSignTasks();
            SignSession signTask = SigSessionFactory.getSigSessionTask(docBytes, sigTempDir);
            if (signTask == null) {
                return getReqStatusResponse(SpsStatusGroup.SigRequest, SpsStatus.IllegalDocType);
            }
            signTask.setDocument(docBytes);
            signTask.setSignerAttribute(srp.getSignerIdAttr());
            signTask.setSignerId(srp.getSignerId());
            signTask.setIdpEntityId(srp.getIdpEntityId());
            String providedReturnUrl = getSigReqProperty(SignRequestParams.Property.returnUrl, optionalProperties);
            String returnUrl = conf.getSpServiceReturnUrl();
            if (providedReturnUrl.length() > 6) {
                returnUrl = providedReturnUrl;
            }
            signTask.setReturnUrl(returnUrl);
            signTask.setSpEntityId(getSigReqProperty(SignRequestParams.Property.spEntityId, optionalProperties));
            signTask.setSignMessage(signMessBytes);
            signTask.setReqSigAlgorithm(getSigReqProperty(SignRequestParams.Property.requestedAlgorithm, optionalProperties));
            signTask.setLastUsed(System.currentTimeMillis());
            signTask.setCertType(srp.getCertType() == null ? CertType.PKC.name() : srp.getCertType().name());
            String loa = Constants.LOA3;
            SignerAuthLoa reqLoa = srp.getLoa();
            if (reqLoa != null) {
                switch (reqLoa) {
                    case loa1:
                        loa = Constants.LOA1;
                        break;
                    case loa2:
                        loa = Constants.LOA2;
                        break;
                    case loa3:
                        loa = Constants.LOA3;
                        break;
                    case loa4:
                        loa = Constants.LOA4;
                        break;
                    default:
                        loa = Constants.LOA3;
                }
            }
            signTask.setSignerAuthLoa(loa);


            //Generate the sign xhtml
            String xhtml;
            // Check if this is a request for a test case
            Map<String, String> extension = srp.getParameters();
            if (extension != null && extension.containsKey("testcase")) {
                String testCase = extension.get("testcase");
                // Get test case reference
                String ref = "";
                if (extension.containsKey("testcaseRef")) {
                    ref = extension.get("testcaseRef");
                }

                if (testCase.equalsIgnoreCase("replay")) {
                    if (!signTaskMap.containsKey(ref)) {
                        return getReqStatusResponse(SpsStatusGroup.SigRequest, SpsStatus.NoSignTask);
                    }
                    SignSession referenceTask = signTaskMap.get(ref);
                    signTask.setSignRequestID(referenceTask.getSignRequestID());
                }
                if (testCase.equalsIgnoreCase("resign")) {
                    if (signTaskMap.containsKey(ref)) {
                        switch (signTask.getDocumentType()) {
                            case XML:
                                signTask.setDocument(signTaskMap.get(ref).getSignedDoc());
                                break;
                            case PDF:
                                signTask.setDocument(signTaskMap.get(ref).getSigFile());
                        }
                    }
                }

                xhtml = testCaseRedirect(signTask, testCase);
            } else {
                xhtml = prepareSignRedirect(signTask);
            }

            if (xhtml == null) {
                return getReqStatusResponse(SpsStatusGroup.SigRequest, SpsStatus.ReqGenError);
            }

            SignRequestXhtml xhtmlResponse = getReqStatusResponse(SpsStatusGroup.Generic, SpsStatus.OK);
            xhtmlResponse.setSignRequestXhtml(xhtml.getBytes(Charset.forName("UTF-8")));
            xhtmlResponse.setTransactionId(signTask.getSignRequestID());

            return xhtmlResponse;
        } catch (Exception ex) {
            Logger.getLogger(SpSupportWs.class.getName()).warning(ex.getMessage());
            return getReqStatusResponse(SpsStatusGroup.SigRequest, SpsStatus.ReqGenError);
        }

    }

//    private SignRequestXhtml getTestCaseReqXhtml(SignRequestParams srp, String testCase) {
//        SupportConfig conf = SpSuppContextParams.getConf();
//        String sigTempDir = SpSuppContextParams.getSigTempDir();
//        Map<String, SignSession> signTaskMap = SpSuppContextParams.getSignTaskMap();
//        List<SignTaskParams> sigTaskRequests = srp.getSigTaskParams();
//
//        // Get test case reference
//        Map<String, String> extension = srp.getExtension();
//        String ref = "";
//        if (extension.containsKey("testcaseRef")) {
//            ref = extension.get("testcaseRef");
//        }
//
//        SignTaskParams stp = sigTaskRequests.get(0);
//        Map<SignRequestParams.Property, String> optionalProperties = srp.getOptionalProperties();
//
//        byte[] docBytes = stp.getTbsDocument();
//        byte[] signMessBytes = getSigReqProperty(SignRequestParams.Property.signMessage, optionalProperties).getBytes(Charset.forName("UTF-8"));
//        cleanupSignTasks();
//
//        SignSession signTask = SigSessionFactory.getSigSessionTask(docBytes, sigTempDir);
//        if (signTask == null) {
//            return getReqStatusResponse(SpsStatusGroup.SigRequest, SpsStatus.illegalDocType);
//        }
//        signTask.setDocument(docBytes);
//        signTask.setSignerAttribute(srp.getSignerIdAttr());
//        signTask.setSignerId(srp.getSignerId());
//        signTask.setIdpEntityId(srp.getIdpEntityId());
//        String providedReturnUrl = getSigReqProperty(SignRequestParams.Property.returnUrl, optionalProperties);
//        String returnUrl = conf.getSpServiceReturnUrl();
//        if (providedReturnUrl.length() > 6) {
//            returnUrl = providedReturnUrl;
//        }
//        signTask.setReturnUrl(returnUrl);
//        signTask.setSpEntityId(getSigReqProperty(SignRequestParams.Property.spEntityId, optionalProperties));
//        signTask.setSignMessage(signMessBytes);
//        signTask.setReqSigAlgorithm(getSigReqProperty(SignRequestParams.Property.requestedAlgorithm, optionalProperties));
//        signTask.setLastUsed(System.currentTimeMillis());
//
//        if (testCase.equalsIgnoreCase("replay")) {
//            if (!signTaskMap.containsKey(ref)) {
//                return getReqStatusResponse(SpsStatusGroup.SigRequest, SpsStatus.noSignTask);
//            }
//            SignSession referenceTask = signTaskMap.get(ref);
//            signTask.setSignRequestID(referenceTask.getSignRequestID());
//        }
//        if (testCase.equalsIgnoreCase("resign")) {
//            if (signTaskMap.containsKey(ref)) {
//                switch (signTask.getDocumentType()) {
//                    case XML:
//                        signTask.setDocument(signTaskMap.get(ref).getSignedDoc());
//                        break;
//                    case PDF:
//                        signTask.setDocument(signTaskMap.get(ref).getSigFile());
//                }
//            }
//        }
//
//        String signRedirect = testCaseRedirect(signTask, testCase);
//
//        if (signRedirect == null) {
//            return getReqStatusResponse(SpsStatusGroup.SigRequest, SpsStatus.ReqGenError);
//        }
//
//        SignRequestXhtml sigReqXhtml = getReqStatusResponse(SpsStatusGroup.Generic, SpsStatus.OK);
//        sigReqXhtml.setSignRequestXhtml(signRedirect.getBytes(Charset.forName("UTF-8")));
//
//        return sigReqXhtml;
//    }
    private SignatureResult getSignatureResult(byte[] signResponse) {
        Map<String, SignSession> signTaskMap = SpSuppContextParams.getSignTaskMap();
        SupportModel model = SpSuppContextParams.getModel();

        SignatureResult sigResult = new SignatureResult();
        SignTaskResult stResult = new SignTaskResult();
        stResult.setParameters(new HashMap<String, String>());
        List<SignTaskResult> strList = new ArrayList<SignTaskResult>();
        strList.add(stResult);
        sigResult.setSignTaskResult(strList);

        cleanupSignTasks();
        ServiceStatus status = SigResponse.processSignResponse(signResponse, signTaskMap);
        sigResult.setTransactionId(status.signTaskID);
        String jsonStatus = model.getGson().toJson(status);
        Map<String, String> params = new HashMap<String, String>();
        params.put("legacyStatus", String.valueOf(Base64Coder.encode(jsonStatus.getBytes(Charset.forName("UTF-8")))));
        sigResult.setParameters(params);


        if (status.respSigValid && status.signedDocValid && status.validResponse) {
            if (status.signTaskID != null && signTaskMap.containsKey(status.signTaskID)) {
                SignSession session = signTaskMap.get(status.signTaskID);
                if (session.getSignedDoc() != null) {
                    stResult.setSignedDoc(session.getSignedDoc());
                } else {
                    stResult.setSignedDoc(FileOps.readBinaryFile(session.getSigFile()));
                }
                stResult.setStatus(getStatus(SpsStatusGroup.Generic, SpsStatus.OK));
            } else {
                // There was no matching sign task
                sigResult.setStatus(getStatus(SpsStatusGroup.Generic, SpsStatus.FailedSigCompletion));
                return sigResult;
            }

        } else {
            // The sign task failed.
            sigResult.setStatus(getStatus(SpsStatusGroup.Generic, SpsStatus.FailedSigCompletion));
            return sigResult;
        }
        sigResult.setSignerId(getSignerId(status.userId));
        sigResult.setStatus(getStatus(SpsStatusGroup.Generic, SpsStatus.OK));
        return sigResult;
    }

    private VerifyResponse getSignatureValidationReport(byte[] signedDoc, String trustPolicy, Map<String, String> parameters) {
        VerifyResponse vr = new VerifyResponse();
        try {
            trustPolicy = trustPolicy != null ? trustPolicy : Constants.VALIDATION_POLICY;
            String validationReport = SignSupportAPI.getValidationReport(new ByteArrayInputStream(signedDoc), trustPolicy);
            vr.setVerifyReport(validationReport.getBytes(Charset.forName("UTF-8")));
            vr.setStatus(getStatus(SpsStatusGroup.SignatureValidation, SpsStatus.OK));
        } catch (Exception ex) {
            vr.setStatus(getStatus(SpsStatusGroup.SignatureValidation, SpsStatus.FailedValidation));
        }
        return vr;
    }

    private String prepareSignRedirect(SignSession signTask) {
        SupportConfig conf = SpSuppContextParams.getConf();
        Map<String, SignSession> signTaskMap = SpSuppContextParams.getSignTaskMap();
        SupportModel model = SpSuppContextParams.getModel();

        String csServiceUrl = conf.getSigServiceRequestUrl();
        byte[] sigRequest = new byte[]{};
        String nonce = "";

        try {
            nonce = signTask.getSignRequestID();
            sigRequest = SigRequest.getRequest(model, signTask);
            signTaskMap.put(nonce, signTask);
        } catch (Exception ex) {
        }

        return XhtmlForm.getSignXhtmlForm(
                XhtmlForm.Type.SIG_REQUEST_FORM,
                csServiceUrl,
                sigRequest,
                nonce);
    }

    private String testCaseRedirect(SignSession signTask, String testcase) {
        SupportConfig conf = SpSuppContextParams.getConf();
        Map<String, SignSession> signTaskMap = SpSuppContextParams.getSignTaskMap();
        SupportModel model = SpSuppContextParams.getModel();

        String csServiceUrl = conf.getSigServiceRequestUrl();
        byte[] sigRequest;
        String nonce;

        nonce = signTask.getSignRequestID();
        if (testcase.equalsIgnoreCase("resign")) {
            sigRequest = SigRequest.getRequest(model, signTask);
        } else {
            sigRequest = TestRequests.getTestCaseRequest(model, signTask, testcase);
        }
        if (!testcase.equalsIgnoreCase("replay")) {
            signTaskMap.put(nonce, signTask);
        }

        return XhtmlForm.getSignXhtmlForm(
                XhtmlForm.Type.SIG_REQUEST_FORM,
                csServiceUrl,
                sigRequest,
                nonce);
    }

    private void cleanupSignTasks() {
        Map<String, SignSession> signTaskMap = SpSuppContextParams.getSignTaskMap();
        long signSessionMaxAge = SpSuppContextParams.getSignSessionMaxAge();

        List<String> deleteKeys = new ArrayList<String>();
        Iterator<String> keys = signTaskMap.keySet().iterator();
        while (keys.hasNext()) {
            String key = keys.next();
            SignSession sigTask = signTaskMap.get(key);
            long lastUsed = sigTask.getLastUsed();
            if (System.currentTimeMillis() > (lastUsed + signSessionMaxAge)) {
                deleteKeys.add(key);
            }
        }
        if (!deleteKeys.isEmpty()) {
            for (String key : deleteKeys) {
                SignSession taskToDelete = signTaskMap.get(key);
                taskToDelete.clear();
                signTaskMap.remove(key);
            }
        }
    }

    private SignRequestXhtml getReqStatusResponse(SpsStatusGroup group, SpsStatus minor) {
        SignRequestXhtml srx = new SignRequestXhtml();
        Status status = getStatus(group, minor);
        srx.setStatus(status);
        String htmlMess = group.getMessage() + " - " + minor.getMessage() + "  <a href='index.jsp'>back</a>";
        srx.setSignRequestXhtml(htmlMess.getBytes(Charset.forName("UTF-8")));
        return srx;
    }

    private Status getStatus(SpsStatusGroup group, SpsStatus minor) {
        Status status = new Status();
        status.setStatusGroup(group.getCode());
        status.setStatusGroupDescription(group.getMessage());
        status.setStatusCode(minor.getCode());
        status.setStatusCodeDescription(minor.getMessage());
        return status;
    }

    private String getSigReqProperty(SignRequestParams.Property prop, Map<SignRequestParams.Property, String> optionalProperties) {
        if (prop == null || optionalProperties == null) {
            return "";
        }
        if (optionalProperties.containsKey(prop)) {
            return optionalProperties.get(prop);
        }
        return "";
    }

    private Map<String, String> getSignerId(List<IdAttribute> userId) {
        Map<String, String> signerId = new HashMap<String, String>();
        for (IdAttribute ida : userId) {
            signerId.put(getOid(ida.name), ida.value);
        }
        return signerId;
    }

    private String getOid(String name) {
        if (Enums.idAttributes.containsKey(name)) {
            return Enums.idAttributes.get(name);
        }
        return name;
    }
}
