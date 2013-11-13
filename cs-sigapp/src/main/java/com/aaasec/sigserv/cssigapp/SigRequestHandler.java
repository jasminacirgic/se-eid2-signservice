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

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.FnvHash;
import com.aaasec.sigserv.cscommon.XhtmlForm;
import com.aaasec.sigserv.cscommon.enums.Enums;
import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.signature.SigVerifyResult;
import com.aaasec.sigserv.cscommon.testdata.TestData;
import com.aaasec.sigserv.cscommon.xmldsig.XMLSign;
import com.aaasec.sigserv.cssigapp.data.DbSignTask;
import com.aaasec.sigserv.cssigapp.data.DbTrustStore;
import com.aaasec.sigserv.cssigapp.data.SignAcceptPageInfo;
import com.aaasec.sigserv.cssigapp.db.SignTaskTable;
import com.aaasec.sigserv.cssigapp.db.TrustStoreTable;
import com.aaasec.sigserv.cssigapp.utils.DefTustStore;
import iaik.x509.X509Certificate;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignRequestExtensionType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignResponseExtensionType;
import x0Assertion.oasisNamesTcSAML2.AudienceRestrictionType;
import x0CoreSchema.oasisNamesTcDss1.InternationalStringType;
import x0CoreSchema.oasisNamesTcDss1.ResultDocument.Result;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument.SignRequest;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument.SignResponse;

/**
 * Sig Request Handler
 */
public class SigRequestHandler {

    private static final long MAX_TIME = 1000 * 60 * 10;
    private String storageLocation;
    private SignTaskTable signDb;
    private String sigTaskDir, sigTaskDbFile;
    private TrustStoreTable trustDb;
    private String confDir, trustDbFile;
    private File pemCertFile;
    private OldReqCleaner cleaner = new OldReqCleaner();
    private Thread cleanThread;

    public SigRequestHandler(String storageLocation) {
        this.storageLocation = storageLocation;
        sigTaskDir = FileOps.getfileNameString(storageLocation, "sigTasks");
        sigTaskDbFile = FileOps.getfileNameString(sigTaskDir, "sigTasks.db");
        signDb = new SignTaskTable(sigTaskDbFile);
        confDir = FileOps.getfileNameString(storageLocation, "conf");
        trustDbFile = FileOps.getfileNameString(confDir, "truststore.db");
        trustDb = new TrustStoreTable(trustDbFile);
        pemCertFile = new File(confDir, "trusted.pem");
        initTrustStore();
    }

    public ReqResult handeSignRequest(byte[] reqXml) {
        ReqResult reqResult;
        byte[] encSigReq = reqXml;
        String reqText = new String(reqXml, Charset.forName("UTF-8"));
        //Cleanup old requests
        removeOldRequests();
        //Get request
        SignRequestDocument sigReqDoc;
        SignRequest sigReq = null;
        SignRequestExtensionType eid2Req = null;
        try {
            sigReqDoc = SignRequestDocument.Factory.parse(new ByteArrayInputStream(reqXml));
            sigReq = sigReqDoc.getSignRequest();
            eid2Req = sigReq.getOptionalInputs().getSignRequestExtension();
        } catch (Exception ex) {
        }
        if (eid2Req == null) {
            return new ReqResult(Enums.ResponseCodeMajor.InsufficientInfo, "", "");
        }

        // Get response URL;
        String spUrl = "";
        try {
            AudienceRestrictionType[] audienceRestrictions = eid2Req.getConditions().getAudienceRestrictionArray();
            for (AudienceRestrictionType audRest : audienceRestrictions) {
                spUrl = audRest.getAudienceArray(0);
            }
        } catch (Exception ex) {
        }

        String id = "";
        try {

            //Check if request is a replay
            id = sigReq.getRequestID();
            DbSignTask dbRecord = signDb.getDbRecord(id);
            if (dbRecord != null) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Replay of old request");
                setErrorResponse(reqResult, encSigReq);
                return reqResult;
            }

            //Check signature
            SigVerifyResult verifySignature = XMLSign.verifySignature(reqXml);
            if (!verifySignature.valid) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Bad signature on request");
                reqResult.message = verifySignature.status;
                setErrorResponse(reqResult, encSigReq);
                return reqResult;
            }
            //Check if signer is in trust store
            Map<BigInteger, DbTrustStore> trustStoreMap = trustDb.getTrustStoreMap();
            //Look for errors
//            Set<BigInteger> keySet = trustStoreMap.keySet();
//            List<String> dbKeys = new ArrayList<String>();
//            for (BigInteger key:keySet){
//                DbTrustStore dbts = trustStoreMap.get(key);
//                
//                dbKeys.add(dbts.getCert().toString(true));
//            }            
            BigInteger pkHash = FnvHash.getFNV1a(verifySignature.cert.getPublicKey().getEncoded());
//            String pkHashString = pkHash.toString(16);
//            String verifyCert = CertificateUtils.getCertificate(verifySignature.cert.getEncoded()).toString(true);
//            

            boolean trustedRequester = false;
            if (trustStoreMap.containsKey(pkHash)) {
                DbTrustStore ts = trustStoreMap.get(pkHash);
                PublicKey tsPubKey = ts.getCert().getPublicKey();
                PublicKey sigPubKey = verifySignature.cert.getPublicKey();
                trustedRequester = Arrays.equals(tsPubKey.getEncoded(), sigPubKey.getEncoded());
//                trustedRequester = tsPubKey.equals(sigPubKey);
            }

            if (!trustedRequester) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Requesting service provider is not in trust store");
                setErrorResponse(reqResult, encSigReq);
                return reqResult;
            }

            //Check age
            long reqTime = eid2Req.getRequestTime().getTimeInMillis();
            if (reqTime + MAX_TIME < System.currentTimeMillis()) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Request has expired");
                setErrorResponse(reqResult, encSigReq);
                return reqResult;
            }

            //Check if request time is in the future
            if (System.currentTimeMillis() + 60000 < reqTime) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Illegal request time");
                setErrorResponse(reqResult, encSigReq);
                return reqResult;
            }

            // Get Idp Entity Id
            String idpEntityId = null;
            try {
                idpEntityId = eid2Req.getIdentityProvider().getStringValue();
            } catch (Exception ex) {
            }
            if (idpEntityId == null) {
                return new ReqResult(Enums.ResponseCodeMajor.InsufficientInfo, id, spUrl, "Missing Identity Provider reference");
            }

            // Store new sign task
//            sigReq.setSignature(null);
//            byte[] stripped = XmlBeansUtil.getBytes(sigReqDoc);
            // Update db with signMessage and JSON data
            String sigMessage = (eid2Req.getSignMessage() == null) ? "" : new String(eid2Req.getSignMessage(), "UTF-8");
//            sigMessage = InputValidator.filter(sigMessage, InputValidator.Rule.HTML_SCRUB);
            SignAcceptPageInfo pageInfo = new SignAcceptPageInfo();
            pageInfo.sigReuestDeclineUrl = spUrl + "?action=declined";
            pageInfo.requesterName = eid2Req.getSignRequester().getStringValue();
            pageInfo.signingInstanceNonce = id;
            // Store dbRecord
            DbSignTask dbSig = new DbSignTask();
            dbSig.setId(id).setRequest(reqXml).setTime(System.currentTimeMillis());
            dbSig.setSignMessage(sigMessage.getBytes(Charset.forName("UTF-8")));
            dbSig.setPageInfo(pageInfo);
            signDb.addOrReplaceRecord(dbSig);

            reqResult = new ReqResult(Enums.ResponseCodeMajor.Success, id, spUrl);
            reqResult.idpEntityId = idpEntityId;

            return reqResult;
        } catch (Exception ex) {
            return new ReqResult(Enums.ResponseCodeMajor.BadRequest, id, spUrl);
        }


    }

    private void initTrustStore() {
        List<X509Certificate> trustedCerts = DefTustStore.getCertificates(pemCertFile);
        Map<BigInteger, DbTrustStore> trustStoreMap = trustDb.getTrustStoreMap();
        Map<BigInteger, DbTrustStore> manualMap = trustDb.getTrustStoreMap("Source", "manual");
        List<BigInteger> trustedPkHash = new LinkedList<BigInteger>();

        // Add new manually trusted to trust store Db
        for (X509Certificate cert : trustedCerts) {
            BigInteger pkHash = FnvHash.getFNV1a(cert.getPublicKey().getEncoded());
            trustedPkHash.add(pkHash);
            if (!trustStoreMap.containsKey(pkHash)) {
                DbTrustStore dbTs = new DbTrustStore();
                dbTs.setCert(cert).setSource("manual");
                trustDb.addOrReplaceRecord(dbTs);
            }
        }
        // Delete manual certs in db that re not supported by pem cert conf file
        Set<BigInteger> keySet = manualMap.keySet();
        for (BigInteger key : keySet) {
            if (!trustedPkHash.contains(key)) {
                DbTrustStore dbTs = manualMap.get(key);
                trustDb.deteleDbRecord(dbTs);
            }
        }
    }

    private void setErrorResponse(ReqResult reqRes, byte[] encSigReq) {
        SignResponseDocument responseDoc = SignResponseDocument.Factory.newInstance();
        SignResponse response = responseDoc.addNewSignResponse();
        String protProfile = "http://id.elegnamnden.se/csig/1.0/eid2-dss/profile";
        String reqId = "";
        try {
            SignRequestDocument reqDoc = SignRequestDocument.Factory.parse(new ByteArrayInputStream(encSigReq));
            SignRequest signRequest = reqDoc.getSignRequest();
            protProfile = signRequest.getProfile();
            reqId = signRequest.getRequestID();
        } catch (Exception ex) {
        }
        response.setProfile(protProfile);
        response.setRequestID(reqId);
        Result result = response.addNewResult();
        InternationalStringType resultMess = result.addNewResultMessage();
        resultMess.setLang("en");
        resultMess.setStringValue(reqRes.message);
        result.setResultMajor(reqRes.code);
        SignResponseExtensionType eid2Resp = response.addNewOptionalOutputs().addNewSignResponseExtension();
        eid2Resp.setRequest(encSigReq);
        eid2Resp.setResponseTime(Calendar.getInstance());

        byte[] responseXml = XmlBeansUtil.getStyledBytes(responseDoc);
        String errorResponseForm = XhtmlForm.getSignXhtmlForm(XhtmlForm.Type.SIG_RESPONSE_FORM,
                reqRes.spUrl, responseXml, reqId);
        reqRes.errorResponse = errorResponseForm;

        // Store testData
        TestData.storeXhtmlResponse(reqId, errorResponseForm);
        TestData.storeResponse(reqId, responseXml);

    }

    /**
     * Injects runnable daemontask, removing requests older than 20 minutes
     */
    private void removeOldRequests() {
        if (running(cleanThread)) {
            return;
        }
        cleanThread = new Thread(cleaner);
        cleanThread.setDaemon(true);
        cleanThread.start();
    }

    private boolean running(Thread thread) {
        return (thread != null && thread.isAlive());
    }

    public class ReqResult {

        public String id;
        public String code;
        public String message;
        public String spUrl;
        public String idpEntityId;
        public String errorResponse = "";

        public ReqResult(Enums.ResponseCodeMajor type, String id, String spUrl) {
            this.id = id;
            code = type.getCode();
            message = type.getMessage();
            this.spUrl = spUrl;
        }

        public ReqResult(Enums.ResponseCodeMajor type, String id, String spUrl, String message) {
            this.id = id;
            code = type.getCode();
            this.message = message;
            this.spUrl = spUrl;
        }
    }

    class OldReqCleaner implements Runnable {

        long lastCleanup = 0;

        public OldReqCleaner() {
        }

        public void run() {
            long current = System.currentTimeMillis();
            //Skip if last cleanup was less than Max Time;
            if (current < lastCleanup + MAX_TIME) {
                return;
            }
            List<DbSignTask> allRecords = signDb.getAllRecords();
            for (DbSignTask sigTask : allRecords) {
                if (current > sigTask.getTime() + MAX_TIME) {
                    signDb.deteleDbRecord(sigTask);
                }
            }
            lastCleanup = System.currentTimeMillis();
        }
    }
}
