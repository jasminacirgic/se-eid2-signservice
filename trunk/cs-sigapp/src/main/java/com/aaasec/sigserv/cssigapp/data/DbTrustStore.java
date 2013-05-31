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
package com.aaasec.sigserv.cssigapp.data;

import com.aaasec.sigserv.cscommon.FnvHash;
import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import com.aaasec.sigserv.cscommon.PEM;
import iaik.x509.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Database model for trust store.
 */
public class DbTrustStore {

    String pkHash;
    String pemCert="", source="";
    X509Certificate cert=null;
    boolean hasCert=false;

    public DbTrustStore() {
    }

    public String getSource() {
        return source;
    }

    public DbTrustStore setSource(String source) {
        this.source = source;
        return this;
    }

    public String getPkHash() {
        return pkHash;
    }

    public DbTrustStore setPkHash(String pkHash) {
        this.pkHash = pkHash;
        return this;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public DbTrustStore setCert(X509Certificate certificate) {
        try {
            this.pemCert = PEM.getPemCert(certificate.getEncoded());
            this.cert=certificate;
            this.pkHash = FnvHash.getFNV1a(certificate.getPublicKey().getEncoded()).toString();
            hasCert=true;
            return this;
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(DbTrustStore.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.pemCert="";
        cert=null;
        hasCert=false;
        return this;
    }

    public String getPemCert() {
        return pemCert;
    }

    public DbTrustStore setPemCert(String pemCert) {
        X509Certificate certificate = CertificateUtils.getCertificate(pemCert);
        try {            
            this.pemCert = PEM.getPemCert(certificate.getEncoded());
            this.cert=certificate;
            this.pkHash = FnvHash.getFNV1a(certificate.getPublicKey().getEncoded()).toString();
            hasCert=true;
            return this;
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(DbTrustStore.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.pemCert="";
        cert=null;
        hasCert=false;
        return this;
    }
}
