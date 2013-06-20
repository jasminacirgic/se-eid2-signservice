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

import com.aaasec.sigserv.cscommon.DocTypeIdentifier;
import com.aaasec.sigserv.cscommon.enums.SigDocumentType;
import com.aaasec.sigserv.csspapp.models.SignSession;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.logging.Logger;

/**
 * Factory class determining and returning an appropriate signature validation
 * object for a given document.
 */
public class SigSessionFactory {

    private static final Logger LOG = Logger.getLogger(SigSessionFactory.class.getName());

    /**
     * Analyzes the type of document provided for signing and returns an
     * appropriate instance of a sign session task object, providing the
     * document type specific functions of the sign support service.
     *
     * @param docBytes the bytes making up the document to be signed
     * @param tempDir the temporary directory where temporary files related to
     * the sign task will be stored
     * @return An instance of a suitable implementation of the SignSession
     * abstract class
     */
    public static SignSession getSigSessionTask(byte[] docBytes, String tempDir) {
        InputStream is = new ByteArrayInputStream(docBytes);
        return getSigSessionTask(is, tempDir);
    }

    /**
     * Analyzes the type of document provided for signing and returns an
     * appropriate instance of a sign session task object, providing the
     * document type specific functions of the sign support service.
     *
     * @param docFile a file holding the document to be signed.
     * @param tempDir the temporary directory where temporary files related to
     * the sign task will be stored
     * @return An instance of a suitable implementation of the SignSession
     * abstract class
     */
    public static SignSession getSigSessionTask(File docFile, String tempDir) {
        try {
            InputStream is = new FileInputStream(docFile);
            return getSigSessionTask(is, tempDir);
        } catch (FileNotFoundException ex) {
            LOG.warning(ex.getMessage());
            return null;
        }
    }

    /**
     * Analyzes the type of document provided for signing and returns an
     * appropriate instance of a sign session task object, providing the
     * document type specific functions of the sign support service.
     *
     * @param is an InputStream providing the bytes of the document to be
     * signed.
     * @param tempDir the temporary directory where temporary files related to
     * the sign task will be stored
     * @return An instance of a suitable implementation of the SignSession
     * abstract class
     */
    public static SignSession getSigSessionTask(InputStream is, String tempDir) {
        SignSession sigSession;
        SigDocumentType docType = DocTypeIdentifier.getDocType(is);

        switch (docType) {
            case PDF:
                sigSession = new PdfSignTask(tempDir);
                return sigSession;
            case XML:
                sigSession = new XmlSignTask(tempDir);
                return sigSession;
            default:
                return null;
        }
    }

}