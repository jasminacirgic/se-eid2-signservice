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
package com.aaasec.sigserv.csspapp.models;

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.enums.SigDocumentType;
import com.aaasec.sigserv.cscommon.signature.SigVerifyResult;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument;

/**
 * Sign Session data class.
 */
public abstract class SignSession {

    protected String tempDir;
    protected SigDocumentType sigDocumentType;
    protected long lastUsed;
    protected byte[] document = null;
    protected byte[] tbsHash;
    protected byte[] transformData;
    protected String hashAlgorithm;
    protected String signRequestID;
    protected File documentFile;
    protected File sigFile;
    protected SignResponseDocument sigResponse;
    protected byte[] sigRequest;
    protected SigVerifyResult signedDocValidity, responseSignatureValidity;
    protected byte[] signedDoc;
    protected byte[] signedPresentationDocument = new byte[]{};
    protected String idpEntityId;
    protected String signerAttribute;
    protected String signerId;
    protected byte[] signMessage;
    protected ServiceStatus status = new ServiceStatus();
    protected String returnUrl;
    protected String spEntityId;
    protected String reqSigAlgorithm;
    protected String certType;
    protected String signerAuthLoa;

    public SignSession(String tempDir, SigDocumentType sigDocumentType) {
        this.tempDir = tempDir;
        this.sigDocumentType = sigDocumentType;
    }

    public SignSession(String tempDir, SigDocumentType sigDocumentType, String requestId) {
        this.tempDir = tempDir;
        this.sigDocumentType = sigDocumentType;
        setSignRequestID(requestId);
    }

    public void setDocument(File tbsFile) {
        document = FileOps.readBinaryFile(tbsFile);
        FileOps.saveByteFile(document, documentFile);
    }

    public void setDocument(InputStream is) {
        // Store result in tempprary file
        BufferedInputStream bufIn = new BufferedInputStream(is);
        try {

            FileOutputStream fos = new FileOutputStream(documentFile);
            byte[] b = new byte[100];
            for (;;) {
                int len = bufIn.read(b);
                if (len == -1) {
                    break;
                } else {
                    fos.write(b, 0, len);
                }
            }
            fos.close();
        } catch (Exception ex) {
            return;
        } finally {
            try {
                bufIn.close();
            } catch (IOException ex) {
                Logger.getLogger(SignSession.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        document = FileOps.readBinaryFile(documentFile);
    }

    public void setDocument(byte[] document) {
        this.document = document;
        FileOps.saveByteFile(document, documentFile);
    }

    public abstract boolean presignDocument(PrivateKey pk, X509Certificate cert, String digestAlgo, String signAlgo);

    public abstract boolean completeSignedDocument(byte[] signature, byte[][] certificateChain, byte[] tbsBytes);

    public final void setSignRequestID(String requestId) {
        this.signRequestID = requestId;
        File oldDocFile = documentFile;
        documentFile = new File(tempDir, requestId + sigDocumentType.getFileSuffix());
        if (!documentFile.getParentFile().exists()) {
            documentFile.mkdirs();
        }
        if (oldDocFile != null && oldDocFile.canRead()) {
            FileOps.copy(oldDocFile, documentFile);
            oldDocFile.delete();
        }

        if (sigFile != null && sigFile.canRead()) {
            sigFile.delete();
        }
        sigFile = new File(tempDir, requestId + "_sig" + sigDocumentType.getFileSuffix());

        documentFile.deleteOnExit();
        sigFile.deleteOnExit();
    }

    public void clear() {
        if (documentFile!=null && documentFile.canRead()) {
            documentFile.delete();
        }
        if (sigFile!=null && sigFile.canRead()) {
            sigFile.delete();
        }
        document = null;
        signedDoc = null;
        signedPresentationDocument = null;
    }

    public File getSigFile() {
        return sigFile;
    }

    public File getDocumentFile() {
        return documentFile;
    }

    public byte[] getSignedDoc() {
        return signedDoc;
    }

    public void setSignedDoc(byte[] signedDocument) {
        this.signedDoc = signedDocument;
    }

    public byte[] getSignedPresentationDocument() {
        return signedPresentationDocument;
    }

    public void setSignedPresentationDocument(byte[] signedPresentationDocument) {
        this.signedPresentationDocument = signedPresentationDocument;
    }

    public long getLastUsed() {
        return lastUsed;
    }

    public void setLastUsed(long lastUsed) {
        this.lastUsed = lastUsed;
    }

    public SigVerifyResult getResponseSignatureValidity() {
        return responseSignatureValidity;
    }

    public void setResponseSignatureValidity(SigVerifyResult responseSignatureValidity) {
        this.responseSignatureValidity = responseSignatureValidity;
    }

    public byte[] getSigRequest() {
        return sigRequest;
    }

    public void setSigRequest(byte[] sigRequest) {
        this.sigRequest = sigRequest;
    }

    public SignResponseDocument getSigResponse() {
        return sigResponse;
    }

    public void setSigResponse(SignResponseDocument sigResponse) {
        this.sigResponse = sigResponse;
    }

    public SigVerifyResult getSignedDocValidity() {
        return signedDocValidity;
    }

    public void setSignedDocValidity(SigVerifyResult signedDocValidity) {
        this.signedDocValidity = signedDocValidity;
    }

    public String getSignRequestID() {
        return signRequestID;
    }

    public byte[] getDocument() {
        return document;
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public void setIdpEntityId(String idpEntityId) {
        this.idpEntityId = idpEntityId;
    }

    public String getSignerAttribute() {
        return signerAttribute;
    }

    public void setSignerAttribute(String signerAttribute) {
        this.signerAttribute = signerAttribute;
    }

    public String getSignerId() {
        return signerId;
    }

    public void setSignerId(String signerId) {
        this.signerId = signerId;
    }

    public byte[] getSignMessage() {
        return signMessage;
    }

    public void setSignMessage(byte[] signMessage) {
        this.signMessage = signMessage;
    }

    public ServiceStatus getStatus() {
        return status;
    }

    public void setStatus(ServiceStatus status) {
        this.status = status;
    }

    public void setReturnUrl(String returnUrl) {
        this.returnUrl = returnUrl;
    }

    public String getReturnUrl() {
        return returnUrl;
    }

    public void setSpEntityId(String spEntityId) {
        this.spEntityId = spEntityId;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public SigDocumentType getDocumentType() {
        return sigDocumentType;
    }

    public byte[] getTbsHash() {
        return tbsHash;
    }

    public byte[] getTransformData() {
        return transformData;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public String getReqSigAlgorithm() {
        return reqSigAlgorithm;
    }

    public void setReqSigAlgorithm(String reqSigAlgorithm) {
        this.reqSigAlgorithm = reqSigAlgorithm;
    }

    public String getCertType() {
        return certType;
    }

    public void setCertType(String certType) {
        this.certType = certType;
    }

    public String getSignerAuthLoa() {
        return signerAuthLoa;
    }

    public void setSignerAuthLoa(String signerAuthLoa) {
        this.signerAuthLoa = signerAuthLoa;
    }
    
}
