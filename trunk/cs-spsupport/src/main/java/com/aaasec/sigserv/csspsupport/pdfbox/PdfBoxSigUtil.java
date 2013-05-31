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

import com.aaasec.sigserv.csspsupport.models.PdfSignModel;
import com.aaasec.sigserv.csspsupport.pdfbox.modifications.CsCOSWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

/**
 * PDF Box signature utilities.
 */
public class PdfBoxSigUtil {

    
    /**
     * This method extracts data from a dummy signature into the PdfBoxModel used
     * in a later stage to update the signature with an externally created signature.
     * @param model A PdfBoxModel for this signature task.
     * @throws IOException 
     */
    public static void parseSignedData(PdfSignModel model) throws IOException {
        CMSSignedData signedData = model.getSignedData();
        SignerInformationStore signerInfos = signedData.getSignerInfos();
        Iterator iterator = signerInfos.getSigners().iterator();
        List<SignerInformation> siList = new ArrayList<SignerInformation>();
        while (iterator.hasNext()) {
            siList.add((SignerInformation) iterator.next());
        }
        if (!siList.isEmpty()) {
            SignerInformation si = siList.get(0);
            model.setCmsSigAttrBytes(si.getEncodedSignedAttributes());
        }
    }

    /**
     * Save the pdf as incremental. This method is a modification of the same
     * method of PDDcoument. This method use an altered COSWriter that allows
     * control over the time used to create the ID of the document. This way it
     * is possible to perform two consecutive signature generation passes that
     * produce the same document hash.
     *
     * @param doc The document being written with signature creation
     * @param input An input file stream of the document being written
     * @param output An output file stream for the result document
     * @param idTime The time in milliseconds from Jan 1st, 1970 GMT when the
     * signature is created. This time is also used to calculate the ID of the
     * document.
     * @throws IOException if something went wrong
     * @throws COSVisitorException if something went wrong
     */
    public static void saveIncremental(PDDocument doc, FileInputStream input, OutputStream output, long idTime) throws IOException, COSVisitorException {
        //update the count in case any pages have been added behind the scenes.
        doc.getDocumentCatalog().getPages().updateCount();
        CsCOSWriter writer = null;
        try {
            // Sometimes the original file will be missing a newline at the end
            // In order to avoid having %%EOF the first object on the same line
            // as the %%EOF, we put a newline here.  If there's already one at
            // the end of the file, an extra one won't hurt. PDFBOX-1051
            output.write("\r\n".getBytes());
            writer = new CsCOSWriter(output, input);
            writer.write(doc, idTime);
            writer.close();
        } finally {
            if (writer != null) {
                writer.close();
            }
        }
    }

    /**
     * A method that updates the PDF PKCS7 object from the model object with a signature,
     * certificates and SignedAttributes obtains from an external source. The model contains
     * 
     * <p>
     * The PKCS7 Signed data found in the model can be created using a different
     * private key and certificate chain. This method effectively replace the signature
     * value and certificate with the replacement data obtained from the model.
     * 
     * @param model A model for this signature replacement operation containing
     * necessary data for the process.
     * @return The bytes of an updated ODF signature PKCS7.
     */
    public static byte[] updatePdfPKCS7(PdfSignModel model) {

        //New variables
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DEROutputStream dout = new DEROutputStream(bout);
        ASN1EncodableVector npkcs7 = new ASN1EncodableVector();
        ASN1EncodableVector nsd = new ASN1EncodableVector();
        ASN1EncodableVector nsi = new ASN1EncodableVector();

        try {
            ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(model.getSignedData().getEncoded()));

            //
            // Basic checks to make sure it's a PKCS#7 SignedData Object
            //
            ASN1Primitive pkcs7;

            try {
                pkcs7 = din.readObject();
            } catch (IOException e) {
                throw new IllegalArgumentException("Illegal PKCS7");
            }
            if (!(pkcs7 instanceof ASN1Sequence)) {
                throw new IllegalArgumentException("Illegal PKCS7");
            }
            ASN1Sequence signedData = (ASN1Sequence) pkcs7;
            ASN1ObjectIdentifier objId = (ASN1ObjectIdentifier) signedData.getObjectAt(0);
            if (!objId.getId().equals(PdfObjectIds.ID_PKCS7_SIGNED_DATA)) {
                throw new IllegalArgumentException("No SignedData");
            }

            //Add Signed data content type to new PKCS7
            npkcs7.add(objId);

            /**
             * SignedData ::= SEQUENCE { version CMSVersion, digestAlgorithms
             * DigestAlgorithmIdentifiers, encapContentInfo
             * EncapsulatedContentInfo, certificates [0] IMPLICIT CertificateSet
             * OPTIONAL, crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
             * signerInfos SignerInfos }
             */
            //Get the SignedData sequence
            ASN1Sequence signedDataSeq = (ASN1Sequence) ((ASN1TaggedObject) signedData.getObjectAt(1)).getObject();
            int sdObjCount = 0;

            // the version
            nsd.add(signedDataSeq.getObjectAt(sdObjCount++));

            // the digestAlgorithms
            nsd.add(signedDataSeq.getObjectAt(sdObjCount++));

            // the possible ecapsulated content info
            nsd.add(signedDataSeq.getObjectAt(sdObjCount++));
            // the certificates. The certs are taken from the input parameters to the method            
            //ASN1EncodableVector newCerts = new ASN1EncodableVector();
            Certificate[] chain = model.getChain();
            ASN1Encodable[] newCerts = new ASN1Encodable[chain.length];
            //for (Certificate nCert : model.getCertChain()) {
            for (int i = 0; i < chain.length; i++) {
                ASN1InputStream cin = new ASN1InputStream(new ByteArrayInputStream(chain[i].getEncoded()));
                newCerts[i] = cin.readObject();

            }
            nsd.add(new DERTaggedObject(false, 0, new DERSet(newCerts)));


            //Step counter past tagged objects
            while (signedDataSeq.getObjectAt(sdObjCount) instanceof ASN1TaggedObject) {
                ++sdObjCount;
            }

            //SignerInfos is the next object in the sequence of Signed Data (first untagged after certs)
            ASN1Set signerInfos = (ASN1Set) signedDataSeq.getObjectAt(sdObjCount);
            if (signerInfos.size() != 1) {
                throw new IllegalArgumentException("Unsupported multiple signer infos");
            }
            ASN1Sequence signerInfo = (ASN1Sequence) signerInfos.getObjectAt(0);
            int siCounter = 0;

            // SignerInfo sequence
            //
            // 0 - CMSVersion 
            // 1 - SignerIdentifier (CHOICE IssuerAndSerialNumber SEQUENCE) 
            // 2 - DigestAglorithmIdentifier
            // 3 - [0] IMPLICIT SignedAttributes SET 
            // 3 - Signature AlgorithmIdentifier 
            // 4 - Signature Value OCTET STRING 
            // 5 - [1] IMPLICIT UnsignedAttributes
            //
            //version
            nsi.add(signerInfo.getObjectAt(siCounter++));

            // signing certificate issuer and serial number
            Certificate sigCert = chain[0];
            ASN1EncodableVector issuerAndSerial = getIssuerAndSerial(sigCert);
            nsi.add(new DERSequence(issuerAndSerial));
            siCounter++;
            
            //Digest AlgorithmIdentifier
            nsi.add(signerInfo.getObjectAt(siCounter++));

            //Add signed attributes from signature service
            ASN1InputStream sigAttrIs = new ASN1InputStream(model.getCmsSigAttrBytes());
            nsi.add(new DERTaggedObject(false, 0, sigAttrIs.readObject()));

            //Step counter past tagged objects (because signedAttrs i optional in the input data)
            while (signerInfo.getObjectAt(siCounter) instanceof ASN1TaggedObject) {
                siCounter++;
            }

            //Signature Alg identifier
            nsi.add(signerInfo.getObjectAt(siCounter++));

            //Add new signature value from signing service
            nsi.add(new DEROctetString(model.getSignatureBytes()));
            siCounter++;

            //Add unsigned Attributes if present
            if (signerInfo.size()>siCounter && signerInfo.getObjectAt(siCounter) instanceof ASN1TaggedObject){
                nsi.add(signerInfo.getObjectAt(siCounter));
            }

            /*
             * Final Assembly
             */
            // Add the SignerInfo sequence to the SignerInfos set and add this to the SignedData sequence
            nsd.add(new DERSet(new DERSequence(nsi)));
            // Add the SignedData sequence as a eplicitly tagged object to the pkcs7 object
            npkcs7.add(new DERTaggedObject(true, 0, new DERSequence(nsd)));


            dout.writeObject((new DERSequence(npkcs7)));
            byte[] pkcs7Bytes = bout.toByteArray();
            dout.close();
            bout.close();

            return pkcs7Bytes;

        } catch (Exception e) {
            throw new IllegalArgumentException(e.toString());
        }
    }


    /**
     * Internal helper method that constructs an IssuerAndSerial object for SignerInfo
     * based on a signer certificate.
     * @param sigCert
     * @return An ASN1EncodableVector holding the IssuerAndSerial ASN.1 sequence.
     * @throws CertificateEncodingException
     * @throws IOException 
     */
    private static ASN1EncodableVector getIssuerAndSerial(Certificate sigCert) throws CertificateEncodingException, IOException {
        ASN1EncodableVector issuerAndSerial = new ASN1EncodableVector();
        ASN1InputStream ain = new ASN1InputStream(sigCert.getEncoded());
        ASN1Sequence certSeq = (ASN1Sequence) ain.readObject();
        ASN1Sequence tbsSeq = (ASN1Sequence) certSeq.getObjectAt(0);

        int counter = 0;
        while (tbsSeq.getObjectAt(counter) instanceof ASN1TaggedObject) {
            counter++;
        }
        //Get serial
        ASN1Integer serial = (ASN1Integer) tbsSeq.getObjectAt(counter);
        counter += 2;

        ASN1Sequence issuerDn = (ASN1Sequence) tbsSeq.getObjectAt(counter);
        //Return the issuer field
        issuerAndSerial.add(issuerDn);
        issuerAndSerial.add(serial);

        return issuerAndSerial;
    }
}
