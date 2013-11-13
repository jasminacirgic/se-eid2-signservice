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
package com.aaasec.sigserv.csspserver.utility;

import com.aaasec.sigserv.cscommon.DocTypeIdentifier;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.XmlUtils;
import com.aaasec.sigserv.cscommon.enums.SigDocumentType;
import static com.aaasec.sigserv.cscommon.enums.SigDocumentType.PDF;
import static com.aaasec.sigserv.cscommon.enums.SigDocumentType.XML;
import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.signature.SigVerifyResult;
import com.aaasec.sigserv.cscommon.xmldsig.XMLSign;
import com.aaasec.sigserv.csspapp.models.ServiceStatus;
import com.aaasec.sigserv.csspserver.models.RequestModel;
import com.aaasec.sigserv.csspserver.models.SpModel;
import com.aaasec.sigserv.csspserver.models.SpSession;
import com.aaasec.sigserv.csspsupport.CertType;
import com.aaasec.sigserv.csspsupport.Property;
import com.aaasec.sigserv.csspsupport.SignRequestParams;
import com.aaasec.sigserv.csspsupport.SignTaskParams;
import com.aaasec.sigserv.csspsupport.SignTaskResult;
import com.aaasec.sigserv.csspsupport.SignatureResult;
import com.aaasec.sigserv.csspsupport.SignerAuthLoa;
import com.aaasec.sigserv.csspsupport.SpSupportWs;
import com.aaasec.sigserv.csspsupport.SpSupportWs_Service;
import com.google.gson.Gson;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.xmlbeans.XmlObject;
import sun.misc.BASE64Decoder;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument;

/**
 * Webb application functions.
 */
public class SpServerLogic {

    private static final Logger LOG = Logger.getLogger(SpServerLogic.class.getName());
    private static Gson gson = SpModel.getGson();

    private SpServerLogic() {
    }

    public static String getDocUploadResponse(RequestModel req, File uploadedFile) {
        req.getSession().newSigningInstance(DocTypeIdentifier.getDocType(uploadedFile));
        SigDocumentType docType = DocTypeIdentifier.getDocType(uploadedFile);
        switch (docType) {
            case XML:
                String xmlTest = XmlUtils.getParsedXMLText(uploadedFile);
                if (xmlTest.length() == 0) {
                    return "Error";
                }
            default:
                String response = getDocSelectResponse(uploadedFile, req);
                uploadedFile.deleteOnExit();
                return response;
        }
    }

    public static String getServerDocResponse(RequestModel req, String fileName) {
        String filePath = FileOps.getfileNameString(SpModel.getDocDir(), fileName);
        File docFile = new File(filePath);
        if (docFile.canRead()) {
            SigDocumentType docType = DocTypeIdentifier.getDocType(docFile);
            req.getSession().newSigningInstance(docType);
            return getDocSelectResponse(docFile, req);
        }
        return "Error";
    }

    public static String getDocSelectResponse(File docFile, RequestModel req) {
        SpSession session = req.getSession();
        session.setDocument(docFile);
        session.getStatus().setSigAcceptStatus(docFile.getName());
        return "OK";
    }

    public static byte[] getXMLdoc(RequestModel req) {
        return req.getSession().getDocument();
    }

    public static void completeSignedDoc(byte[] sigResponse, RequestModel req) {
        SpSession session = req.getSession();

        try { // Call Web Service Operation
            SpSupportWs_Service service = new SpSupportWs_Service();
            SpSupportWs port = service.getSpSupportWsPort();
            // Process result
            SignatureResult result = port.completeSigning(sigResponse);
            SignTaskResult signTaskResult = result.getSignTaskResult().get(0);
            byte[] signedDoc = signTaskResult.getSignedDoc();
            String jsonStatus = getLegacyJsonData(result);
            ServiceStatus status = SpModel.getGson().fromJson(jsonStatus, ServiceStatus.class);
            status.documentName = session.getDocumentFile().getName();
            session.setStatus(status);
            session.setSignRequestID(status.signTaskID);
            try {
                SignResponseDocument responseDoc = getResponseXmlObject(sigResponse);
                SigVerifyResult verifySignature = XMLSign.verifySignature(sigResponse);
                status.respSigValid = verifySignature.valid;
                session.setSigResponse(responseDoc);
                session.setSigRequest(responseDoc.getSignResponse().getOptionalOutputs()
                        .getSignResponseExtension().getRequest());
            } catch (Exception ex) {
            }
            if (status.signedDocValid) {
                switch (session.getDocumentType()) {
                    case XML:
                        try {
                            XmlObject signedXmlObject = XmlObject.Factory.parse(new ByteArrayInputStream(signedDoc));
                            session.setSignedDoc(XmlBeansUtil.getBytes(signedXmlObject));
                            session.setSignedPresentationDocument(XmlBeansUtil.getStyledBytes(signedXmlObject));
                        } catch (Exception ex) {
                        }
                        break;
                    case PDF:
                        FileOps.saveByteFile(signedDoc, session.getSigFile());
                }
            }

        } catch (Exception ex) {
            LOG.warning("failed to parse and use sign response");
        }
    }

    private static String getLegacyJsonData(SignatureResult result) {
        BASE64Decoder b64 = new BASE64Decoder();
        String jsonStatus = "";

        try {
            //Get Legacy status Json data
            Map<String, String> paramMap = getSignatureResultParamMap(result);
            if (paramMap.containsKey("legacyStatus")) {
                String legacyStatus = paramMap.get("legacyStatus");
                jsonStatus = new String(b64.decodeBuffer(legacyStatus), Charset.forName("UTF-8"));
            }
        } catch (Exception ex) {
        }
        return jsonStatus;
    }

    private static Map<String, String> getSignatureResultParamMap(SignatureResult result) {
        Map<String, String> parameterMap = new HashMap<String, String>();
        try {

            List<SignatureResult.Parameters.Entry> entryList = result.getParameters().getEntry();
            for (SignatureResult.Parameters.Entry entry : entryList) {
                parameterMap.put(entry.getKey(), entry.getValue());
            }
        } catch (Exception ex) {
        }
        return parameterMap;
    }

    public static SignResponseDocument getResponseXmlObject(byte[] sigResponse) {
        try {
            return SignResponseDocument.Factory.parse(new ByteArrayInputStream(sigResponse));
        } catch (Exception ex) {
            return null;
        }
    }

    public static String prepareSignRedirect(RequestModel req, boolean includeSignMessage) {
        SpSession session = req.getSession();
        byte[] tbsDoc = session.getDocument();
        if (includeSignMessage) {
            session.setSignMessage(SigRequestMessage.getMessage(req));
        } else {
            session.setSignMessage(null);
        }
        try { // Call Web Service Operation
            SpSupportWs_Service service = new SpSupportWs_Service();
            SpSupportWs port = service.getSpSupportWsPort();
            // Initialize WS operation arguments
            SignRequestParams signRequestParams = new SignRequestParams();

            signRequestParams.setCertType(CertType.QC_SSCD);
            signRequestParams.setLoa(SignerAuthLoa.LOA_3);
            signRequestParams.setIdpEntityId(session.getIdpEntityId());
            signRequestParams.setSignerIdAttr(session.getSignerAttribute());
            signRequestParams.setSignerId(session.getSignerId());
            setProperty(signRequestParams, Property.REQUESTED_ALGORITHM, session.getReqSigAlgorithm());
            // Uncomment the following line to include a sign message dialogue
            if (session.getSignMessage() != null) {
                setProperty(signRequestParams, Property.SIGN_MESSAGE, new String(session.getSignMessage(), Charset.forName("UTF-8")));
            }
            //setProperty(signRequestParams, Property.RETURN_URL, returnUrl);

            List<SignTaskParams> sigTaskParams = signRequestParams.getSignTaskParams();
            SignTaskParams stp = new SignTaskParams();
            sigTaskParams.add(stp);
            //stp.setSigType(SigType.XML);
            //stp.setAdesType(AdesType.NONE);
            stp.setTbsDocument(tbsDoc);

            // process result
            com.aaasec.sigserv.csspsupport.SignRequestXhtml result = port.signRequest(signRequestParams);
            String xhtml = new String(result.getSignRequestXhtml(), Charset.forName("UTF-8"));

            return xhtml;

        } catch (Exception ex) {
            return "Failed to generate sign request";
        }

    }

    public static void setProperty(SignRequestParams signRequestParams, Property property, String value) {
        SignRequestParams.Properties op = signRequestParams.getProperties();
        if (op == null) {
            op = new SignRequestParams.Properties();
            signRequestParams.setProperties(op);
        }
        List<SignRequestParams.Properties.Entry> entryList = op.getEntry();
        SignRequestParams.Properties.Entry entry = new SignRequestParams.Properties.Entry();
        entry.setKey(property);
        entry.setValue(value);
        entryList.add(entry);
    }

    public static String processFileUpload(HttpServletRequest request, HttpServletResponse response, RequestModel req) {
        // Create a factory for disk-based file items
        Map<String, String> paraMap = new HashMap<String, String>();
        File uploadedFile = null;
        boolean uploaded = false;
        DiskFileItemFactory factory = new DiskFileItemFactory();
        String uploadDirName = FileOps.getfileNameString(SpModel.getDataDir(), "uploads");
        FileOps.createDir(uploadDirName);
        File storageDir = new File(uploadDirName);
        factory.setRepository(storageDir);

        // Create a new file upload handler
        ServletFileUpload upload = new ServletFileUpload(factory);
        try {
            // Parse the request
            List<FileItem> items = upload.parseRequest(request);
            for (FileItem item : items) {
                if (item.isFormField()) {
                    String name = item.getFieldName();
                    String value = item.getString();
                    paraMap.put(name, value);
                } else {
                    String fieldName = item.getFieldName();
                    String fileName = item.getName();
                    if (fileName.length() > 0) {
                        String contentType = item.getContentType();
                        boolean isInMemory = item.isInMemory();
                        long sizeInBytes = item.getSize();
                        uploadedFile = new File(storageDir, fileName);
                        try {
                            item.write(uploadedFile);
                            uploaded = true;
                        } catch (Exception ex) {
                            LOG.log(Level.SEVERE, null, ex);
                        }
                    }
                }

            }
            if (uploaded) {
                return SpServerLogic.getDocUploadResponse(req, uploadedFile);
            } else {
                if (paraMap.containsKey("xmlName")) {
                    return SpServerLogic.getServerDocResponse(req, paraMap.get("xmlName"));
                }
            }
        } catch (FileUploadException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        return "";
    }

    public static String getDocList() {
        File docDir = new File(SpModel.getDocDir());
        String[] fileList = docDir.list();
        List<String> docName = new ArrayList<String>();
        try {
            for (String name : fileList) {
                if (name.toLowerCase().endsWith(".xml") || name.toLowerCase().endsWith(".pdf")) {
                    docName.add(name);
                }
            }
        } catch (Exception ex) {
        }
        return gson.toJson(docName);
    }
}
