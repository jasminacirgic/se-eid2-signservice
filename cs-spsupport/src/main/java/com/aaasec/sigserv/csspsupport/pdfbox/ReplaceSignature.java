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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Logger;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * PDF Box signature interface for the complete signing operation.
 */
public class ReplaceSignature implements SignatureInterface {

    private static final Logger LOG = Logger.getLogger(ReplaceSignature.class.getName());
    private static BouncyCastleProvider provider = new BouncyCastleProvider();
    private CMSSignedData signedData;
    private PDDocument doc;
    private PdfSignModel model;

    public CMSSignedData getSignedData() {
        return signedData;
    }

    public PDDocument getDoc() {
        return doc;
    }

    public ReplaceSignature(PdfSignModel model) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.model = model;
    }

    public File resignPDF() throws IOException, COSVisitorException,
            SignatureException {
        File document = new File(model.getOriginalLoc());

        byte[] buffer = new byte[8 * 1024];
        if (document == null || !document.exists()) {
            throw new RuntimeException("Document for signing does not exist");
        }

        // creating output document and prepare the IO streams.
        String name = document.getName();
        String substring = name.substring(0, name.lastIndexOf("."));

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
        doc = PDDocument.load(document);

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
        PdfBoxSigUtil.saveIncremental(doc, fis, fos, model.getSigningAndIdTime());

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
     * This method replaces necessary parts from a previous dummy signature with
     * a Certificate chain, signature value and signedAttrs from a remote
     * signature service.
     * </p>
     */
    public byte[] sign(InputStream content) throws SignatureException,
            IOException {
        return PdfBoxSigUtil.updatePdfPKCS7(model);
    }

}
