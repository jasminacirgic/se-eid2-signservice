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
import com.aaasec.sigserv.cscommon.enums.SigDocumentType;
import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.xmldsig.XMLSign;
import com.aaasec.sigserv.cscommon.xmldsig.XmlSignatureInfo;
import com.aaasec.sigserv.csspapp.models.SignSession;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Model for XML sign tasks.
 */
public class XmlSignTask extends SignSession {

    private XmlSignatureInfo xmlSignInfo;

    public XmlSignTask(String tempDir) {
        super(
                tempDir,
                SigDocumentType.XML,
                new BigInteger(64, new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes())).toString(16));
    }

    @Override
    public boolean presignDocument(PrivateKey pk, X509Certificate cert, String hashAlgo, String sigAlgo) {

        try {
            xmlSignInfo = XMLSign.getTBSInfo(document, pk, cert, hashAlgo, sigAlgo, null);
            tbsHash = xmlSignInfo.getDigest();
            transformData = xmlSignInfo.getCanonicalSignedInfo();
            hashAlgorithm = ASN1Utils.getHashAlgofromTbsData(xmlSignInfo.getTbsDigestInfo());
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    public boolean completeSignedDocument(byte[] signatureValue, byte[][] responseCertChain, byte[] tbsBytes) {
        try {
            Document signedDoc = xmlSignInfo.getSignedDoc();
            NodeList sigs = signedDoc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");

            if (sigs.getLength() == 0) {
                return false;
            }
            Node sigValNode = null;
            Node x509Data = null;
            List<Node> certNodes = new ArrayList<Node>();

            Node sig = sigs.item(sigs.getLength() - 1);
            NodeList sigChilds = sig.getChildNodes();
            for (int i = 0; i < sigChilds.getLength(); i++) {
                Node item = sigChilds.item(i);
                if (item.getNodeName().endsWith("SignatureValue")) {
                    sigValNode = item;
                }
                if (item.getNodeName().endsWith("KeyInfo")) {
                    NodeList kiNodes = item.getChildNodes();
                    for (int j = 0; j < kiNodes.getLength(); j++) {
                        Node kiNode = kiNodes.item(j);
                        if (kiNode.getNodeName().endsWith("X509Data")) {
                            x509Data = kiNode;
                        }

                    }
                }
            }
            NodeList x509Nodes = x509Data.getChildNodes();
            for (int i = 0; i < x509Nodes.getLength(); i++) {
                Node x509Node = x509Nodes.item(i);
                if (x509Node.getNodeName().endsWith("X509Certificate")) {
                    certNodes.add(x509Node);
                }
            }

            sigValNode.setTextContent(String.valueOf(Base64Coder.encode(signatureValue)));
            for (int i = 0; i < certNodes.size(); i++) {
                Node certNode = certNodes.get(i);
                certNode.setTextContent(String.valueOf(Base64Coder.encode(responseCertChain[i])));
            }
            // include rest of certs in chain
            for (int i = certNodes.size(); i < responseCertChain.length; i++) {
                Node newCertNode = certNodes.get(0).cloneNode(false);
                newCertNode.setTextContent(String.valueOf(Base64Coder.encode(responseCertChain[i])));
                x509Data.appendChild(newCertNode);
            }
            setSignedDocValidity(XMLSign.verifySignature(signedDoc));
            try {
                setSignedDoc(XmlBeansUtil.getBytes(XmlObject.Factory.parse(signedDoc)));
                setSignedPresentationDocument(XmlBeansUtil.getStyledBytes(XmlObject.Factory.parse(signedDoc)));
            } catch (XmlException ex) {
                Logger.getLogger(XmlSignTask.class.getName()).warning(ex.getMessage());
            }
            return true;
        } catch (Exception ex) {
            return false;
        }

    }
}