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

import java.security.NoSuchAlgorithmException;
import javax.xml.crypto.dsig.DigestMethod;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Digest algorithm enumeration.
 */
public enum DigestAlgorithm {

    SHA1("SHA-1", "1.3.14.3.2.26", DigestMethod.SHA1), SHA256("SHA-256", "2.16.840.1.101.3.4.2.1",
            DigestMethod.SHA256), SHA512("SHA-512", "2.16.840.1.101.3.4.2.3", DigestMethod.SHA512);

    private String name;

    private String oid;

    private String xmlId;

    private DigestAlgorithm(String name, String oid, String xmlId) {
        this.name = name;
        this.oid = oid;
        this.xmlId = xmlId;
    }

    /**
     * Return the algorithm corresponding to the name
     * 
     * @param algoName
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static DigestAlgorithm getByName(String algoName) throws NoSuchAlgorithmException {
        if ("SHA-1".equals(algoName) || "SHA1".equals(algoName)) {
            return SHA1;
        }
        if ("SHA-256".equals(algoName)) {
            return SHA256;
        }
        if ("SHA-512".equals(algoName)) {
            return SHA512;
        }
        throw new NoSuchAlgorithmException("unsupported algo: " + algoName);
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the oid
     */
    public String getOid() {
        return oid;
    }

    /**
     * @return the xmlId
     */
    public String getXmlId() {
        return xmlId;
    }

    /**
     * Gets the ASN.1 algorithm identifier structure corresponding to this digest algorithm
     * 
     * @return the AlgorithmIdentifier
     */
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        /*
         * The recommendation (cf. RFC 3380 section 2.1) is to omit the parameter for SHA-1, but some implementations
         * still expect a NULL there. Therefore we always include a NULL parameter even with SHA-1, despite the
         * recommendation, because the RFC states that implementations SHOULD support it as well anyway
         */
        return new AlgorithmIdentifier(new DERObjectIdentifier(this.getOid()), new DERNull());
    }

}

