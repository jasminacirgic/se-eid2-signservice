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

import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.enums.Enums;
import com.aaasec.sigserv.cscommon.xmldsig.XMLSign;
import iaik.asn1.ASN1;
import iaik.asn1.ASN1Object;
import iaik.asn1.ObjectID;
import org.apache.xml.security.signature.XMLSignature;

/**
 * ASN.1 Utilities.
 */
public class ASN1Utils {

    int[] sha256der = new int[]{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};

    public static String getSigAlgofromTbsData(byte[] pkcs1Data) {


        try {
            String b64inp = String.valueOf(Base64Coder.encode(pkcs1Data));

            ASN1 obj = new ASN1(pkcs1Data);
            ASN1Object a1o = obj.toASN1Object();
            if (a1o.countComponents() != 2) {
                return "";
            }
            //Get hash objectId
            ASN1Object oidObj = a1o.getComponentAt(0).getComponentAt(0);
            if (oidObj instanceof ObjectID) {
                ObjectID hashOid = (ObjectID) oidObj;
                if (Enums.digestNames.containsKey(hashOid.getID())) {
                    String algoName = Enums.digestNames.get(hashOid.getID());

                    if (algoName.equals("SHA256")) {
                        return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
                    }
                    if (algoName.equals("SHA1")) {
                        return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
                    }
                }
            }

        } catch (Exception ex) {
            return "";
        }
        return "";
    }

    public static String getHashAlgofromTbsData(byte[] pkcs1Data) {


        try {
            String b64inp = String.valueOf(Base64Coder.encode(pkcs1Data));

            ASN1 obj = new ASN1(pkcs1Data);
            ASN1Object a1o = obj.toASN1Object();
            if (a1o.countComponents() != 2) {
                return "";
            }
            //Get hash objectId
            ASN1Object oidObj = a1o.getComponentAt(0).getComponentAt(0);
            if (oidObj instanceof ObjectID) {
                ObjectID hashOid = (ObjectID) oidObj;
                if (Enums.digestNames.containsKey(hashOid.getID())) {
                    String algoName = Enums.digestNames.get(hashOid.getID());

                    if (algoName.equals("SHA256")) {
                        return XMLSign.SHA256;
                    }
                    if (algoName.equals("SHA1")) {
                        return XMLSign.SHA1;
                    }
                }
            }

        } catch (Exception ex) {
            return "";
        }
        return "";
    }
}
