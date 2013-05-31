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
package com.aaasec.sigserv.csspsupport.pdfbox;

/**
 * Signature algorithm enumeration.
 */
public enum SignatureAlgorithm {
    RSA_WITH_SHA1("1.2.840.113549.1.1.5", "http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
    RSA_WITH_SHA256("1.2.840.113549.1.1.11", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
    ECDSA_WITH_SHA256("1.2.840.10045.4.3.2","http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
    
    private String oid;
    private String xmlId;

    private SignatureAlgorithm(String oid, String xmlId) {
        this.oid = oid;
        this.xmlId = xmlId;
    }

    public String getOid() {
        return oid;
    }

    public String getXmlId() {
        return xmlId;
    }
    
    public static SignatureAlgorithm getAlgorithmByOid(String oidString){
        SignatureAlgorithm[] values = values();
        for (SignatureAlgorithm sigAlgo:values){
            if (oidString.equals(sigAlgo.getOid())){
                return sigAlgo;
            }
        }
        throw new IllegalArgumentException("No such algorithm");
    }
    public static SignatureAlgorithm getAlgorithmByXmlId(String xmlId){
        SignatureAlgorithm[] values = values();
        for (SignatureAlgorithm sigAlgo:values){
            if (xmlId.equals(sigAlgo.getXmlId())){
                return sigAlgo;
            }
        }
        throw new IllegalArgumentException("No such algorithm");
    }
}
