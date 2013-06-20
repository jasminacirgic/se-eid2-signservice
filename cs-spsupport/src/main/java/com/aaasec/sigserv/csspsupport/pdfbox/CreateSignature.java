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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;


/**
 * PDF Box signature interface.
 */
public class CreateSignature implements SignatureInterface {

    private static final Logger LOG = Logger.getLogger(CreateSignature.class.getName());
    private static BouncyCastleProvider provider = new BouncyCastleProvider();
    private PrivateKey privKey;
    private Certificate[] cert;
    private PdfSignModel model;

    /**
     * Initialize the signature creator with a keystore (pkcs12) and pin that
     * should be used for the signature.
     *
     * @param keystore is a pkcs12 keystore.
     * @param pin is the pin for the keystore / private key
     */
    public CreateSignature(KeyStore keystore, char[] pin, PdfSignModel model) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        /*
         * grabs the first alias from the keystore and get the private key. An
         * alternative method or constructor could be used for setting a specific
         * alias that should be used.
         */
        this.model = model;
        Enumeration<String> aliases = keystore.aliases();
        String alias = null;
        if (aliases.hasMoreElements()) {
            alias = aliases.nextElement();
        } else {
            throw new RuntimeException("Could not find alias");
        }
        privKey = (PrivateKey) keystore.getKey(alias, pin);
        cert = keystore.getCertificateChain(alias);
    }

    /**
     * Initialize the signature creator with a private key and certificate chain
     * that should be used for the signature.
     *
     * @param pKey is a private key.
     * @param certs is an Array of certs
     */
    public CreateSignature(PrivateKey pKey, Certificate[] certs, PdfSignModel model) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        
        this.model = model;
        privKey = pKey;
        cert = certs;
    }

    /**
     * Initialize the signature creator with a private key and certificate that
     * should be used for the signature.
     *
     * @param pKey is a private key.
     * @param certs is a signature cert
     */
    public CreateSignature(PrivateKey pKey, Certificate sigCert, PdfSignModel model) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {

        this.model = model;
        privKey = pKey;
        cert = new Certificate[]{sigCert};
    }

    /**
     * Signs the given pdf file.
     */
    public File signPDF() throws IOException, COSVisitorException,
            SignatureException {
        byte[] buffer = new byte[8 * 1024];
        File document = new File(model.getOriginalLoc());
        if (document == null || !document.exists()) {
            throw new RuntimeException("Document for signing does not exist");
        }

        File outputDocument = new File(model.getSignedLoc());
        FileInputStream fis = new FileInputStream(document);
        FileOutputStream fos = new FileOutputStream(outputDocument);

        int c;
        while ((c = fis.read(buffer)) != -1) {
            fos.write(buffer, 0, c);
        }
        fis.close();
        fis = new FileInputStream(outputDocument);

        // load document
        PDDocument doc = PDDocument.load(document);

        // create signature dictionary
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
        // subfilter for basic and PAdES Part 2 signatures
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        if (model.getSignerName() != null) {
            signature.setName(model.getSignerName());
        }
        if (model.getSignerLocation() != null) {
            signature.setLocation(model.getSignerLocation());
        }
        if (model.getReasonForSigning() != null) {
            signature.setReason(model.getReasonForSigning());
        }

        // the signing date, needed for valid signature
        Calendar sigDate = Calendar.getInstance();
        sigDate.setTime(new Date(model.getSigningAndIdTime()));
        signature.setSignDate(sigDate);

        // register signature dictionary and sign interface
        if (model.getOptions() == null) {
            doc.addSignature(signature, this);
        } else {
            doc.addSignature(signature, this, model.getOptions());
        }

        // write incremental (only for signing purpose)
        PdfBoxSigUtil.saveIncremental (doc,fis, fos, model.getSigningAndIdTime());

        return outputDocument;
    }

    /**
     * <p>
     * SignatureInterface implementation.
     * </p>
     *
     * <p>
     * This method will be called from inside of the pdfbox and create the pkcs7
     * signature. The given InputStream contains the bytes that are provided by
     * the byte range.
     * </p>
     *
     * <p>
     * This method is for internal use only.
     * </p>
     *
     * <p>
     * Here the user should use his favorite cryptographic library and implement
     * a pkcs7 signature creation.
     * </p>
     */
    public byte[] sign(InputStream content) throws SignatureException,
            IOException {
        List<Certificate> certList = Arrays.asList(cert);
        CMSProcessableInputStream input = new CMSProcessableInputStream(content);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        CertStore certStore = null;
        try {
            Store certs = new JcaCertStore(certList);
            certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), provider);

            gen.addSigner(privKey, (X509Certificate) certList.get(0), CMSSignedGenerator.DIGEST_SHA256);

            gen.addCertificates(certs);
            CMSSignedData signedData = gen.generate(input, false, provider);
            model.setSignedData(signedData);
            
            PdfBoxSigUtil.parseSignedData(model);
            return signedData.getEncoded();
        } catch (Exception e) {
            // should be handled
            System.err.println("Error while creating pkcs7 signature.");
            e.printStackTrace();
        }
        throw new RuntimeException("Problem while preparing signature");
    }
}
/**
 * Wrap a InputStream into a CMSProcessable object for bouncy castle. It's an
 * alternative to the CMSProcessableByteArray.
 *
 * @author Thomas Chojecki
 *
 */
class CMSProcessableInputStream implements CMSProcessable {

    InputStream in;

    public CMSProcessableInputStream(InputStream is) {
        in = is;
    }

    public Object getContent() {
        return null;
    }

    public void write(OutputStream out) throws IOException, CMSException {
        // read the content only one time
        byte[] buffer = new byte[8 * 1024];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        in.close();
    }    
    
}
