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
package com.aaasec.sigserv.csspsupport.signtask;

import com.aaasec.sigserv.cscommon.enums.SigDocumentType;
import com.aaasec.sigserv.cscommon.signature.SigVerifyResult;
import com.aaasec.sigserv.csspapp.models.SignSession;
import com.aaasec.sigserv.csspsupport.models.PdfSignModel;
import com.aaasec.sigserv.csspsupport.pdfbox.CreateSignature;
import com.aaasec.sigserv.csspsupport.pdfbox.ReplaceSignature;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

/**
 * Model for PDF sign tasks.
 */
public class PdfSignTask extends SignSession {

    private PdfSignModel sigModel;

    public PdfSignTask(String tempDir) {
        super(
                tempDir,
                SigDocumentType.PDF,
                new BigInteger(64, new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes())).toString(16));
    }

    @Override
    public boolean presignDocument(PrivateKey pk, X509Certificate cert, String hashAlgo, String sigAlgo) {
        long signTime = System.currentTimeMillis();
        try {

            sigModel = new PdfSignModel(documentFile.getAbsolutePath(), sigFile.getAbsolutePath(),
                    signTime, "Signer", null, null, null);
            CreateSignature signingTask = new CreateSignature(pk, cert, sigModel);
            signingTask.signPDF();
            transformData = sigModel.getCmsSigAttrBytes();
            return true;
        } catch (Exception ex) {
            Logger.getLogger(PdfSignTask.class.getName()).warning(ex.toString());
            return false;
        }
    }

    @Override
    public boolean completeSignedDocument(byte[] signature, byte[][] certificateChain, byte[] tbsBytes) {
        try {
            X509Certificate[] certChain = getCertChain(certificateChain);
            sigModel.setChain(certChain);
            sigModel.setSignatureBytes(signature);
            if (tbsBytes != null) {
                sigModel.setCmsSigAttrBytes(tbsBytes);
            }
            ReplaceSignature signingTask = new ReplaceSignature(sigModel);
            try {
                signingTask.resignPDF();
            } catch (Exception ex) {
                Logger.getLogger(PdfSignTask.class.getName()).warning(ex.toString());
                setSignedDocValidity(new SigVerifyResult("Faild signing"));
                return false;
            }
            setSignedDocValidity(new SigVerifyResult(certChain[0]));
            return true;
        } catch (Exception ex) {
            return false;
        }

    }

    private static X509Certificate[] getCertChain(byte[][] certChainData) {
        X509Certificate[] chain = new X509Certificate[certChainData.length];
        int i = 0;
        for (byte[] certBytes : certChainData) {
            chain[i++] = getX509Cert(certBytes);
        }
        return chain;
    }

    private static X509Certificate getX509Cert(byte[] certData) {

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try {
                X509Certificate X509Cert = (java.security.cert.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certData));
                return X509Cert;
            } catch (CertificateException e) {
                return null;
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}