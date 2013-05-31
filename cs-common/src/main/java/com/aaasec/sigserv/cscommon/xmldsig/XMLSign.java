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
package com.aaasec.sigserv.cscommon.xmldsig;

import com.aaasec.sigserv.cscommon.XmlUtils;
import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.signature.SigVerifyResult;
import com.aaasec.sigserv.cscommon.signature.SigVerifyResult.IndivdualSignatureResult;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyValue;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xmlbeans.XmlObject;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.ec.ECUtil;
import org.w3.x2000.x09.xmldsig.ReferenceType;
import org.w3.x2000.x09.xmldsig.SignatureDocument;
import org.w3.x2000.x09.xmldsig.SignatureType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * XML Signature functions
 */
public class XMLSign {

    public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    // From SignatureMethod
    public static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    // From DigestMethod
    public static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
    public static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final Logger LOG = Logger.getLogger(XMLSign.class.getName());

    static {
        org.apache.xml.security.Init.init();
    }

    public static SignedXmlDoc getSignedXML(byte[] xmlData, PrivateKey key, X509Certificate cert, Node sigParent) {
        return getSignedXML(xmlData, key, cert, SHA256, RSA_SHA256, sigParent);
    }

    public static SignedXmlDoc getSignedXML(byte[] xmlData, PrivateKey key, X509Certificate cert, String digestAlgo, String sigAlgo, Node sigParent) {
        SignedXmlDoc signedDoc = null;
        try {
            signedDoc = signXML(xmlData, key, cert, digestAlgo, sigAlgo, sigParent);
            signedDoc.sigDocBytes = XmlUtils.getCanonicalDocText(signedDoc.doc);

            return signedDoc;

        } catch (Exception ex) {
            LOG.log(Level.SEVERE, null, ex);
        }

        return signedDoc;
    }

    public static XmlSignatureInfo getTBSInfo(byte[] xmlData, PrivateKey key, X509Certificate cert, String hashAlgo, String sigAlgo, Node sigParent) {
        try {
            SignedXmlDoc signedXML = signXML(xmlData, key, cert, hashAlgo, sigAlgo, sigParent);
            XmlSignatureInfo sigInfo = getDigestInfo(signedXML, cert.getPublicKey());
            return sigInfo;

        } catch (Exception ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private static XmlSignatureInfo getDigestInfo(SignedXmlDoc signedXML, PublicKey pubKey) throws ParserConfigurationException, SAXException, IOException, NullPointerException {
        XmlSignatureInfo tbsSigInfo = new XmlSignatureInfo();
        Document cloneDoc = getDoc(XmlUtils.getCanonicalDocText(signedXML.doc));
        XmlSigData xmlSigData = getSignatureData(cloneDoc);

        if (xmlSigData != null) {
            /*
             * targetTBS contains ASN.1 providing 2 parameters (E.g for sha 1)
             * SEQUENCE(2 elem)
             *   SEQUENCE(2 elem)
             *     OBJECT IDENTIFIER1.3.14.3.2.26                                 //Sha1 OID
             *     NULL                                                           //Null paramenters
             *   OCTET STRING(20 byte) 4ADD3EDF460E9BFF6EE6E8C1BC06F91BC685D4E7   //Sha1 Hash
             * 
             */

            tbsSigInfo.setSigDoc(xmlSigData.signature);
            tbsSigInfo.setSignatureType(xmlSigData.sigType);
            tbsSigInfo.setSignatureXml(xmlSigData.signatureXml);
            tbsSigInfo.setTbsDigestInfo(signedXML.getPkcs1Sha256TbsDigest());
            tbsSigInfo.setDigest(signedXML.getSha256Hash());
            tbsSigInfo.setCanonicalSignedInfo(signedXML.signedInfoOctets);
            tbsSigInfo.setSignedDoc(signedXML.doc);

            return tbsSigInfo;
        }
        return null;
    }

    private static SignedXmlDoc signXML(byte[] xmlData, PrivateKey key, X509Certificate cert, Node sigParent) {
        return signXML(xmlData, key, cert, SHA256, RSA_SHA256, sigParent);
    }

    private static SignedXmlDoc signXML(byte[] xmlData, PrivateKey key, X509Certificate cert,
            String digestMethod, String signatureAlgo, Node sigParent) {
        return signXml(new ByteArrayInputStream(xmlData), key, cert, digestMethod, signatureAlgo, sigParent);
    }

    public static SignedXmlDoc signXml(InputStream docIs, PrivateKey privateKey, PublicKey pk, String digestMethod, String signatureAlgo, Node sigParent) {
        return signXml(docIs, privateKey, null, pk, digestMethod, signatureAlgo, sigParent);
    }

    public static SignedXmlDoc signXml(InputStream docIs, PrivateKey privateKey, X509Certificate cert, String digestMethod, String signatureAlgo, Node sigParent) {
        return signXml(docIs, privateKey, cert, null, digestMethod, signatureAlgo, sigParent);

    }

    public static SignedXmlDoc signXml(InputStream docIs, PrivateKey privateKey, X509Certificate cert, PublicKey pk, String digestMethod, String signatureAlgo, Node sigParent) {
        byte[] signedHash;
        try {
            // Instantiate the document to be signed
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            dbFactory.setNamespaceAware(true);
            Document doc = dbFactory.newDocumentBuilder().parse(docIs);

            //For adding id attribute
            //String id = String.valueOf(System.currentTimeMillis());

            // sign the whole contract and no signature and exclude condition1
            String xpathStr = "not(ancestor-or-self::ds:Signature)";

            {
                org.apache.xml.security.signature.XMLSignature signature =
                        new org.apache.xml.security.signature.XMLSignature(doc, "", signatureAlgo);

                if (sigParent != null) {
                    String namespaceURI = sigParent.getNamespaceURI();
                    String nodeName = sigParent.getNodeName();
                    NodeList nl = doc.getElementsByTagNameNS(namespaceURI, nodeName);
                    if (nl.getLength() > 0) {
                        Element sigObjNode = (Element) nl.item(0);
                        sigObjNode.appendChild(signature.getElement());
                    } else {
                        doc.getFirstChild().appendChild(signature.getElement());
                    }
                } else {
                    doc.getFirstChild().appendChild(signature.getElement());
                }

                //For adding ID attribute
                //signature.setId(id);

                String rootnamespace = doc.getNamespaceURI();
                boolean rootprefixed = (rootnamespace != null) && (rootnamespace.length() > 0);
                String rootlocalname = doc.getNodeName();
                Transforms transforms = new Transforms(doc);
                XPathContainer xpath = new XPathContainer(doc);

                xpath.setXPathNamespaceContext("ds", Constants.SignatureSpecNS);
                xpath.setXPath(xpathStr);
                transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
                transforms.addTransform(Transforms.TRANSFORM_XPATH,
                        xpath.getElementPlusReturns());
                signature.addDocument("", transforms, digestMethod);

                {
                    if (cert == null) {
                        signature.getKeyInfo().add(new KeyValue(doc, pk));
                    } else {
                        X509Data x509Data = new X509Data(doc);
                        x509Data.addCertificate(cert);
                        signature.getKeyInfo().add(x509Data);
                    }
                    signature.sign(privateKey);
                    signedHash = signature.getSignedInfo().getCanonicalizedOctetStream();
                }

                //Set Id attribute value on signature
//                try {
//                    Node sigValueNode = signature.getElement()
//                            .getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "SignatureValue").item(0);
//                    Attr idAttr = doc.createAttribute("Id");
//                    idAttr.setValue(id);
//                    sigValueNode.getAttributes().setNamedItem(idAttr);
//                } catch (Exception ex) {
//                }
            }
            return new SignedXmlDoc(signedHash, doc);
        } catch (Exception ex) {
            return null;
        }
    }

    public static SigVerifyResult verifySignature(byte[] signedXml) {
        try {
            Document doc = getDoc(signedXml);
            return verifySignature(doc);
        } catch (Exception ex) {
            Logger.getLogger(XMLSign.class.getName()).warning(ex.getMessage());
            return new SigVerifyResult("Unable to parse document");
        }


    }

    public static SigVerifyResult verifySignature(Document doc) {
        SigVerifyResult result = new SigVerifyResult();
        // Get signature nodes;
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            return new SigVerifyResult("No Signature");
        }
        //Get document ID attribute
        NamedNodeMap rootAttr = doc.getFirstChild().getAttributes();
        Node idAttrNode = rootAttr.getNamedItem("ID");
        boolean hasId = false;
        String docID = null;
        if (idAttrNode != null) {
            try {
                docID = idAttrNode.getTextContent();
                hasId = docID!=null;
            } catch (Exception ex) {
            }
        }

        //Verify all signatures
        for (int i = 0; i < nl.getLength(); i++) {
            //Check if this signature covers the document
            boolean coversDoc=false;
            try {
                Node sigNode = nl.item(i);
                SignatureType sigType = SignatureDocument.Factory.parse(sigNode).getSignature();
                ReferenceType[] referenceArray = sigType.getSignedInfo().getReferenceArray();
                for (ReferenceType ref:referenceArray){
                    if (hasId){
                        if (ref.getURI().equals("#"+docID)){
                            coversDoc=true;
                        }
                    } else {
                        if (ref.getURI().equals("")){
                            coversDoc=true;
                        }
                    }
                }
                //Verify the signature if it covers the doc
                if(coversDoc){
                    IndivdualSignatureResult newResult = result.addNewIndividualSignatureResult();
                    newResult.thisSignatureNode=sigNode;
                    verifySignatureElement(doc, (Element)sigNode, newResult);
                } 

            } catch (Exception ex) {
            }
        }
        result.consolidateResults();

        return result;
    }

    public static void verifySignatureElement(Document doc, Element sigElement, SigVerifyResult.IndivdualSignatureResult result) {
        try {
            org.apache.xml.security.signature.XMLSignature signature = new org.apache.xml.security.signature.XMLSignature(sigElement, "");
            signature.addResourceResolver(new OfflineResolver());
            KeyInfo ki = signature.getKeyInfo();

            if (ki == null) {
                result.thisStatus = "No Key Info";
                return;
            }
            X509Certificate cert = signature.getKeyInfo().getX509Certificate();

            if (cert == null) {
                result.thisStatus = "No Certificate in signature";
                return;
            }
            result.thisValid = signature.checkSignatureValue(cert);
            result.thisStatus = result.thisValid ? "Signature valid" : "Signature validation failed";
            result.thisCert=cert;
            return;
        } catch (Exception ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        }
        result.thisStatus = "Signature parsing error";
        return;
    }

//    public static SigVerifyResult legacyVerifySignature(byte[] xmlData) {
//        try {
//            return legacyVerifySignature(getDoc(xmlData));
//        } catch (ParserConfigurationException ex) {
//            LOG.log(Level.WARNING, null, ex);
//        } catch (SAXException ex) {
//            LOG.log(Level.WARNING, null, ex);
//        } catch (IOException ex) {
//            LOG.log(Level.WARNING, null, ex);
//        }
//        return null;
//    }
//
//    public static SigVerifyResult legacyVerifySignature(Document doc) {
//        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
//        if (nl.getLength() == 0) {
//            return new SigVerifyResult("No Signature");
//        }
//
//        Node signatureNode = nl.item(nl.getLength() - 1);
//        if (null == signatureNode) {
//            return new SigVerifyResult("No Signature");
//        }
//
//
//        KeyInfoKeySelector keyInfoKeySelector = new KeyInfoKeySelector();
//        DOMValidateContext valContext = new DOMValidateContext(
//                keyInfoKeySelector, signatureNode);
//        XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");
//        XMLSignature signature;
//        try {
//            signature = xmlSignatureFactory.unmarshalXMLSignature(valContext);
//        } catch (MarshalException ex) {
//            return new SigVerifyResult("XML signature parse error: " + ex.getMessage());
//        }
//        boolean coreValidity;
//        try {
//            coreValidity = signature.validate(valContext);
//        } catch (XMLSignatureException ex) {
//            return new SigVerifyResult("XML signature error: " + ex.getMessage());
//        }
//
//        // TODO: check what has been signed
//
//        if (coreValidity) {
//            return new SigVerifyResult(keyInfoKeySelector.getCertificate());
//        }
//
//        // Check core validation status if core signature validation failed.
//        StringBuilder b = new StringBuilder();
//
//        try {
//            boolean sv = signature.getSignatureValue().validate(valContext);
//            b.append("signature validation status: ").append(sv).append("<br />");
//            if (sv == false) {
//                // Check the validation status of each Reference.
//                Iterator i = signature.getSignedInfo().getReferences().iterator();
//                for (int j = 0; i.hasNext(); j++) {
//                    boolean refValid = ((Reference) i.next()).validate(valContext);
//                    b.append("ref[").append(j).append("] validity status: ").append(refValid).append("<br />");
//                }
//            }
//        } catch (XMLSignatureException ex) {
//            b = new StringBuilder();
//            b.append("Core Signature validation failure");
//        }
//
//        return new SigVerifyResult(keyInfoKeySelector.getCertificate(), b.toString(), coreValidity);
//    }

    public static Document getDoc(String xml) throws ParserConfigurationException, SAXException, IOException {
        return getDoc(xml.getBytes("UTF-8"));
    }

    public static Document getDoc(byte[] xmlData) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        InputStream is = new ByteArrayInputStream(xmlData);
        Document doc = builder.parse(is);
        return doc;
    }

    public static XmlSigData getSignatureData(Document doc) {
        NodeList sel = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

        if (sel.getLength() > 0) {
            try {
                Node item = sel.item(sel.getLength() - 1);

                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                DocumentBuilder builder = dbf.newDocumentBuilder();
                Document sDoc = builder.newDocument();
                sDoc.adoptNode(item);
                sDoc.appendChild(item);
                byte[] sigTxt = XmlBeansUtil.getBytes(XmlObject.Factory.parse(sDoc));
                SignatureType sigType = SignatureDocument.Factory.parse(sDoc).getSignature();

                return new XmlSigData(sigType, sDoc, sigTxt);

            } catch (Exception ex) {
//                Logger.getLogger(XMLSign.class.getName()).log(Level.WARNING, null, ex);
            }
        }
        return null;
    }

    public static X509Certificate getCertificate(byte[] encoded) {
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            InputStream is = new ByteArrayInputStream(encoded);
            X509Certificate generateCertificate = (X509Certificate) fact.generateCertificate(is);
            is.close();
            return generateCertificate;
        } catch (IOException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private static String str(byte[] bytes) {
        return new String(bytes, Charset.forName("UTF-8"));
    }

    public static byte[] rsaVerify(byte[] signature, PublicKey pubKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, pubKey);
            byte[] cipherData = cipher.doFinal(signature);
            return cipherData;
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static byte[] rsaSign(byte[] pkcs1PaddedHash, PrivateKey privKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privKey);
            byte[] cipherData = cipher.doFinal(pkcs1PaddedHash);
            return cipherData;
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static EcdsaSigValue ecdsaSignDigest(byte[] digest, PrivateKey privKey) {
        try {
            ECDSASigner ecdsa = new ECDSASigner();
            CipherParameters param = ECUtil.generatePrivateKeyParameter(privKey);


            ecdsa.init(true, param);
            BigInteger[] signature = ecdsa.generateSignature(digest);
            EcdsaSigValue sigVal = new EcdsaSigValue(signature[0], signature[1]);
            return sigVal;
        } catch (InvalidKeyException ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static boolean ecdsaVerifyDigest(byte[] digest, byte[] signature, PublicKey pubKey) {
        return ecdsaVerifyDigest(digest, EcdsaSigValue.getInstance(signature), pubKey);
    }

    public static boolean ecdsaVerifyDigest(byte[] digest, EcdsaSigValue signature, PublicKey pubKey) {
        try {
            ECDSASigner ecdsa = new ECDSASigner();
            CipherParameters param = ECUtil.generatePublicKeyParameter(pubKey);
            ecdsa.init(false, param);
            EcdsaSigValue sigVal = EcdsaSigValue.getInstance(signature);
            return ecdsa.verifySignature(digest, sigVal.getR(), sigVal.getS());
        } catch (Exception ex) {
            Logger.getLogger(XMLSign.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public static EcdsaSigValue ecdsaSignDataWithSha256(byte[] data, PrivateKey privKey) {
        try {
            Signature ecdsaSigner = Signature.getInstance("SHA256/ECDSA", "BC");
            ecdsaSigner.initSign(privKey, new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes()));
            ecdsaSigner.update(data);
            byte[] asn1Signature = ecdsaSigner.sign();

            ASN1InputStream a1i = new ASN1InputStream(asn1Signature);
            ASN1Sequence a1s = ASN1Sequence.getInstance(a1i.readObject());
            EcdsaSigValue sigVal = new EcdsaSigValue(a1s);

            return sigVal;
        } catch (Exception ex) {
        }
        return null;
    }

    public static boolean ecdsaVerifySignedDataWithSHA256(byte[] data, byte[] signature, PublicKey pubKey) {
        return ecdsaVerifySignedDataWithSHA256(data, EcdsaSigValue.getInstance(signature), pubKey);

    }

    public static boolean ecdsaVerifySignedDataWithSHA256(byte[] data, EcdsaSigValue signature, PublicKey pubKey) {
        try {
            EcdsaSigValue sigVal = EcdsaSigValue.getInstance(signature);
            byte[] asn1Signature = sigVal.toASN1Object().getEncoded();

            Signature ecdsaSigner = Signature.getInstance("SHA256/ECDSA", "BC");
            ecdsaSigner.initVerify(pubKey);
            ecdsaSigner.update(data);
            return ecdsaSigner.verify(asn1Signature);
        } catch (Exception ex) {
        }
        return false;
    }

    public static class XmlSigData {

        public SignatureType sigType;
        public Document signature;
        public byte[] signatureXml;

        public XmlSigData() {
        }

        public XmlSigData(SignatureType sigType, Document signature, byte[] signatureXml) {
            this.sigType = sigType;
            this.signature = signature;
            this.signatureXml = signatureXml;
        }
    }
}