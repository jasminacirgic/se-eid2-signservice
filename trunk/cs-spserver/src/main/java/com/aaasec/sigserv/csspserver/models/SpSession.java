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
package com.aaasec.sigserv.csspserver.models;

import com.aaasec.sigserv.cscommon.enums.SigDocumentType;
import com.aaasec.sigserv.csspapp.models.SignSession;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * Service provider web application session.
 */
public class SpSession extends SignSession {

    private BigInteger sessionID;

    public SpSession(BigInteger sessionID, String tempDir) {
        super(tempDir, SigDocumentType.Unknown);
        this.sessionID = sessionID;
    }

    public BigInteger getSessionID() {
        return sessionID;
    }

    public void newSigningInstance(SigDocumentType docType) {
        sigDocumentType = docType;
        setSignRequestID(new BigInteger(64, new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes())).toString(16));
    }

    @Override
    public boolean presignDocument(PrivateKey pk, X509Certificate cert, String hashAlgo, String sigAlgo) {
        return false;
    }

    @Override
    public boolean completeSignedDocument(byte[] signature, byte[][] certificateChain, byte[] tbsBytes) {
        return false;
    }
}
