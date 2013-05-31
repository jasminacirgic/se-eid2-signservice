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
package com.aaasec.sigserv.csspapp;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * This class defines a Java API for accessing services from a Central Signing
 * Support service. <p> The support service is available in the form of a
 * deployable .war, which ideally should be deployed on the same server as where
 * the service provider service using this API is deployed, or at least on the
 * same local network. However, it is quite possible to locate the support
 * service anywhere if appropriate security measures are taken, such as through
 * VPN protection. <p> In addition to obtaining services from a central signing
 * support service, this API also provides a method for validating a signed
 * document using an external TSL Trust signature validation service.
 * Communication with such service should be SSL/TLS protected and appropriate
 * measures should be added to verify the origin of the signature validation
 * report data, through appropriate checks of the server certificate. <p> This
 * API communicates with associated services through HTTP POST and HTTP GET
 * requests. Before any of the API methods are called, this API must be
 * initialized by setting appropriate values of the following parameters (using
 * their associated setter functions): <p>
 * <code>maxMessageLength</code> The maximum length of any data provided to the
 * API using InputStream objects (Default set to 500 kBytes). <p>
 * <code>spSupportUrl</code> The URL to the central signing support service. <p>
 * <code>tempFileLocation</code> A file folder where this API can store
 * temporary files.<p>
 * <code>validationServiceUrl</code> The URL to the signature validation service
 * (Only required if such service is used) <p>
 * <code>validationPolicy</code> The name of the validation policy used to
 * validate signed document (Only required if a validation service is used) <p>
 *
 * @author Stefan Santesson, 3xA Security AB (stefan@aaa-sec.com) on behalf of
 * E-legitimatioinsnämnden (Licensing terms TBD)
 */
public class SignSupportAPI {

    private static final Logger LOG = Logger.getLogger(SignSupportAPI.class.getName());
    private static int maxMessageLength = 500000;
    private static String spSupportUrl;
    private static String validationServiceUrl;
    private static String validationPolicy;
    private static Random rng = new Random(System.currentTimeMillis());
    private static String tempFileLocation;

    /**
     * Dummy constructor, preventing instantiation
     */
    private SignSupportAPI() {
    }

    /**
     * Sets the URL for the Central signing support service
     *
     * @param spSupportUrl
     */
    public static void setSpSupportUrl(String spSupportUrl) {
        SignSupportAPI.spSupportUrl = spSupportUrl;
    }

    /**
     * Sets the maximum message length that will be allowed in the exchange of
     * data between the requesting service and the central signing support
     * service.
     *
     * @param messageMaxLength Integer specifying the maximum number of bytes
     */
    public static void setMaxMessageLength(int messageMaxLength) {
        SignSupportAPI.maxMessageLength = messageMaxLength;
    }

    /**
     * Sets the URL for a signature validation service
     *
     * @param validationServiceUrl
     */
    public static void setValidationServiceUrl(String validationServiceUrl) {
        SignSupportAPI.validationServiceUrl = validationServiceUrl;
    }

    /**
     * Sets the name of the validation policy that is used when performing
     * signature validation
     *
     * @param validationPolicy name of the validation policy
     */
    public static void setValidationPolicy(String validationPolicy) {
        SignSupportAPI.validationPolicy = validationPolicy;
    }

    /**
     * Specifies the directory where temporary files are stored, holding return
     * data from http post and http get requests.
     *
     * @param tempFileLocation full path name of the temporary file directory
     */
    public static void setTempFileLocation(String tempFileLocation) {
        SignSupportAPI.tempFileLocation = tempFileLocation;
        createDir(tempFileLocation);
    }

    /**
     * Send a HTTP POST message to the central signing support service,
     * requesting a XHTML page to be passed to the client to initiate the
     * central signing process. This XHTML contains a form with a signed signing
     * request and a post script that causes the client to post the signing
     * request to the designated central signing server.
     *
     * @param docInputStream An Input stream providing the bytes of the XML
     * document to be signed
     * @param signerIdAttr A string representing the attribute OID of the signer
     * identity. E.g. "1.2.752.29.4.13", not including any type declaratioins,
     * such as "urn:oid:".
     * @param signerId A string holding the signers identity value in the
     * identified attribute
     * @param idpEntityId The entityID of the IdP that should identify the
     * signer in the central signing service
     * @param signMessage A html message to be displayed to the signer in the
     * central signing service
     * @return A XHTML document that will initiate the central signing process
     * through a form post when sent to the signer's web browser.
     */
    public static String signRequest(InputStream docInputStream, String signerIdAttr, String signerId,
            String idpEntityId, byte[] signMessage) {

        return signRequest(docInputStream, signerIdAttr, signerId, idpEntityId, null, null, signMessage, null);
    }

    /**
     * Send a HTTP POST message to the central signing support service,
     * requesting a XHTML page to be passed to the client to initiate the
     * central signing process. This XHTML contains a form with a signed signing
     * request and a post script that causes the client to post the signing
     * request to the designated central signing server.
     *
     * @param xmlDocIs An Input stream providing the bytes of the document to be
     * signed
     * @param signerIdAttr A string representing the attribute OID of the signer
     * identity. E.g. "1.2.752.29.4.13", not including any type declaratioins,
     * such as "urn:oid:".
     * @param signerId A string holding the signers identity value in the
     * identified attribute
     * @param idpEntityId The entityID of the IdP that should identify the
     * signer in the central signing service
     * @param spEntityId The entityID of the service provider requesting a
     * signature. If this parameter is empty, then the default configured SP
     * entity ID will be selected.
     * @param returnUrl The URL where the response message is returned from the
     * signing service. This parameter. If this string is null or empty, the
     * pre-configured return URL in the support service is used.
     * @param signMessage A html message to be displayed to the signer in the
     * central signing service
     * @param sigAlgorithm A URI identifier of a requested signature algorithm.
     * If this string is null or empty, the default algorithm will be used.
     * @return A XHTML document that will initiate the central signing process
     * through a form post when sent to the signer's web browser.
     */
    public static String signRequest(InputStream xmlDocIs, String signerIdAttr, String signerId,
            String idpEntityId, String returnUrl, String spEntityId, byte[] signMessage, String sigAlgorithm) {

        String encodedSignMess = signMessage == null ? "" : b64Eencode(signMessage);
        returnUrl = returnUrl == null ? "" : returnUrl;
        spEntityId = spEntityId == null ? "" : spEntityId;
        sigAlgorithm = sigAlgorithm == null ? "" : sigAlgorithm;

        String reqXhtml = null;
        Map<String, String> queryMap = new HashMap<String, String>();
        queryMap.put("action", "sign");
        queryMap.put("idattr", signerIdAttr);
        queryMap.put("id", signerId);
        queryMap.put("idp", idpEntityId);
        queryMap.put("returnurl", returnUrl);
        queryMap.put("sp", spEntityId);
        queryMap.put("signmess", encodedSignMess);
        queryMap.put("sigalgo", sigAlgorithm);
        byte[] response = httpPost(spSupportUrl, xmlDocIs, queryMap);
        if (response != null) {
            reqXhtml = new String(response, Charset.forName("UTF-8"));
        }
        return reqXhtml;
    }

    /**
     * This call sends a request to the SP Support service to generate a
     * testcase request to the signature service.
     *
     * @param docInputStream An Input stream providing the bytes of the document
     * to be signed
     * @param signerIdAttr A string representing the attribute OID of the signer
     * identity. E.g. "1.2.752.29.4.13", not including any type declaratioins,
     * such as "urn:oid:".
     * @param signerId A string holding the signers identity value in the
     * identified attribute
     * @param idpEntityId The entityID of the IdP that should identify the
     * signer in the central signing service
     * @param signMessage A html message to be displayed to the signer in the
     * central signing service
     * @param ref A reference to a previous request relevant for the test-case.
     * This is only applicable for the replay test-case.
     * @param testCase A string identifying the test-case. The test cases are:
     * <p> <code>oldReq</code> Generates a request with old date. <p>
     * <code>predatedReq</code> Generates a request with a date set in the
     * future <p> <code>badReqSig</code> Generates a request signed by a valid
     * requester but with a bad signature. <p> <code>unknownRequester</code>
     * Generates a request signed by an unknown entity. <p> <code>replay</code>
     * Replays a previous request identified by the <code>ref</code> parameter.
     * @return A XHTML document that will initiate the central signing process
     * through a form post when sent to the signer's web browser.
     */
    public static String testCaseRequest(InputStream docInputStream, String signerIdAttr, String signerId,
            String idpEntityId, byte[] signMessage, String ref, String testCase) {

        return testCaseRequest(docInputStream, signerIdAttr, signerId, idpEntityId, null, null, signMessage, null, ref, testCase);

    }

    /**
     * This call sends a request to the SP Support service to generate a
     * testcase request to the signature service.
     *
     * @param xmlDocIs An Input stream providing the bytes of the XML document
     * to be signed
     * @param signerIdAttr A string representing the attribute OID of the signer
     * identity. E.g. "1.2.752.29.4.13", not including any type declaratioins,
     * such as "urn:oid:".
     * @param signerId A string holding the signers identity value in the
     * identified attribute
     * @param idpEntityId The entityID of the IdP that should identify the
     * signer in the central signing service
     * @param spEntityId The entityID of the service provider requesting a
     * signature. If this parameter is empty, then the default configured SP
     * entity ID will be selected.
     * @param returnUrl The URL where the response message is returned from the
     * signing service. This parameter. If this string is null or empty, the
     * pre-configured return URL in the support service is used.
     * @param signMessage A html message to be displayed to the signer in the
     * central signing service
     * @param sigAlgorithm A URI identifier of a requested signature algorithm.
     * If this string is null or empty, the default algorithm will be used.
     * @param ref A reference to a previous request relevant for the test-case.
     * This is only applicable for the replay test-case.
     * @param testCase A string identifying the test-case. The test cases are:
     * <p> <code>oldReq</code> Generates a request with old date. <p>
     * <code>predatedReq</code> Generates a request with a date set in the
     * future <p> <code>badReqSig</code> Generates a request signed by a valid
     * requester but with a bad signature. <p> <code>unknownRequester</code>
     * Generates a request signed by an unknown entity. <p> <code>replay</code>
     * Replays a previous request identified by the <code>ref</code> parameter.
     * @return A XHTML document that will initiate the central signing process
     * through a form post when sent to the signer's web browser.
     */
    public static String testCaseRequest(InputStream xmlDocIs, String signerIdAttr, String signerId,
            String idpEntityId, String returnUrl, String spEntityId, byte[] signMessage, String sigAlgorithm, String ref, String testCase) {

        String encodedSignMess = signMessage == null ? "" : b64Eencode(signMessage);
        returnUrl = returnUrl == null ? "" : returnUrl;
        spEntityId = spEntityId == null ? "" : spEntityId;
        sigAlgorithm = sigAlgorithm == null ? "" : sigAlgorithm;

        String reqXhtml = null;
        Map<String, String> queryMap = new HashMap<String, String>();
        queryMap.put("action", "testcase");
        queryMap.put("idattr", signerIdAttr);
        queryMap.put("id", signerId);
        queryMap.put("idp", idpEntityId);
        queryMap.put("ref", ref);
        queryMap.put("returnurl", returnUrl);
        queryMap.put("sp", spEntityId);
        queryMap.put("testcase", testCase);
        queryMap.put("signmess", encodedSignMess);
        queryMap.put("sigalgo", sigAlgorithm);
        byte[] response = httpPost(spSupportUrl, xmlDocIs, queryMap);
        if (response != null) {
            reqXhtml = new String(response, Charset.forName("UTF-8"));
        }
        return reqXhtml;

    }

    /**
     * Sends a signing response message obtained from the central signing
     * service to the central signing support service for processing and
     * validation. The central signing service will process that response and
     * compare it with earlier sign requests (max 10 minutes old). If a matching
     * request is found a signed document will be created by adding the
     * signature received in the response to the document received in the
     * request.
     *
     * @param sigResponse The bytes of the signing response
     * @return A JSON object holding status information about the result from
     * processing the signing response. The JSON object holds the following
     * values:
     *
     * <p> <code>"status"</code>: "response" if a response has been received and
     * processed, <p> <code>"signTaskID"</code>: The unique identifier of this
     * sign task, <p> <code>"documentName"</code>: (empty) Not set by the
     * support service, <p> <code>"respSigValid"</code>: boolean true if the
     * response was correctly signed, <p> <code>"signedDocValid"</code>: boolean
     * true true if the constucted document has a valid signature, <p>
     * <code>"validResponse"</code>: boolean true if the response indicate a
     * successfull central signing, <p> <code>"responseCode"</code>: "101" for
     * successful signing, <p> <code>"responseMessage"</code>: "OK" for
     * successful signing, <p> <code>"signingTime"</code>: Date and time for
     * signing (Note that this is only a presentation string for the time. A
     * machine readable time is provided in the sign response XML), *      * <p> <code>"userId"</code>: An array, holding signers identity
     * attributes. Each element in the array holds the
     * elements <code>"name"</code> (attribute id) and <code>"value"</code>
     * (attribute value),
     * <p> <code>"pathLen"</code>: The number of certs in the signer cert path.
     *
     */
    public static String signResponse(byte[] sigResponse) {
        String reqXhtml = null;
        Map<String, String> queryMap = new HashMap<String, String>();
        queryMap.put("action", "response");
        byte[] response = httpPost(spSupportUrl, sigResponse, queryMap);
        if (response != null) {
            reqXhtml = new String(response, Charset.forName("UTF-8"));
        }
        return reqXhtml;

    }

    /**
     * Gets the signed document base64 encoded bytes identified by the sign task
     * ID. This call can be done up until 10 minutes after the signed document
     * was created.
     *
     * @param signTaskId identifier of the signing task. This is the value of
     * the <code>"signTaskID"</code> parameter in the JSON status report
     * obtained through the <code>signResponse</code> method.
     * @return signed XML document produced through the sign task with the
     * specified signTaskId.
     */
    public static byte[] getSignedDoc(String signTaskId) {
        Map<String, String> queryMap = new HashMap<String, String>();
        queryMap.put("action", "getsigned");
        queryMap.put("id", signTaskId);
        queryMap.put("parameter", "b64");
        byte[] response = httpGet(spSupportUrl, queryMap);
        String b64String = new String(response, Charset.forName("UTF-8"));
        byte[] parsedXml = null;
        try {
            parsedXml = b64Decode(b64String);
        } catch (Exception ex) {
        }
        return parsedXml;
    }

    /**
     * Returns a Url for obtaining the signed document.
     *
     * @param sigTaskId identifier of the signing task. This is the value of *
     * the <code>"signTaskID"</code> parameter in the JSON status report
     * obtained through the <code>signResponse</code> method.
     * @return A URL specifying the location of the signed XML document. This
     * URL is valid 10 minutes after the signed document is created.
     */
    public static URL getSignedDocumentUrl(String sigTaskId) {
        Map<String, String> queryMap = new HashMap<String, String>();
        queryMap.put("action", "getsigned");
        queryMap.put("id", sigTaskId);
        queryMap.put("parameter", "binary");

        URL url = null;
        try {
            url = new URL(spSupportUrl + "?" + getRequestQueryData(null, queryMap));
        } catch (Exception ex) {
        }
        return url;
    }

    /**
     * Sends a signed XML document for validation to a preconfigured signature
     * validation service.
     *
     * @param xmlDocIs An input stream providing the bytes of the signed
     * document
     * @return A string representation of the validation report object. If the
     * configured validation service is a TSL Trust signature validation
     * service, then the signature validation response is an XML report
     * according to a defined schema.
     */
    public static String getValidationReport(InputStream xmlDocIs) {
        return getValidationReport(xmlDocIs, validationPolicy);
    }

    /**
     * Sends a signed XML document for validation to a preconfigured signature
     * validation service.
     *
     * @param xmlDocIs An input stream providing the bytes of the signed
     * document
     * @param policy The policy under which the validation is performed.
     * @return A string representation of the validation report object. If the
     * configured validation service is a TSL Trust signature validation
     * service, then the signature validation response is an XML report
     * according to a defined schema.
     */
    public static String getValidationReport(InputStream xmlDocIs, String policy) {
        String sigValReport = null;
        Map<String, String> queryMap = new HashMap<String, String>();
        queryMap.put("action", "postverify");
        queryMap.put("policy", policy);
        queryMap.put("id", "Eid2 Signed Document");
        byte[] response = httpPost(validationServiceUrl, xmlDocIs, queryMap);
        if (response != null) {
            sigValReport = new String(response, Charset.forName("UTF-8"));
        }
        return sigValReport;

    }

    private static byte[] httpPost(String serviceUrl, byte[] inData, Map<String, String> valueMap) {
        return httpPost(serviceUrl, new ByteArrayInputStream(inData), valueMap);
    }

    private static byte[] httpPost(String serviceUrl, InputStream inData, Map<String, String> valueMap) {
        byte[] response = null;
        try {
            URL url = new URL(serviceUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");

            OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
            try {
                wr.write(getRequestQueryData(inData, valueMap));
                wr.flush();
            } catch (Exception ex) {
            } finally {
                wr.close();
            }

            try {

                int responseCode = conn.getResponseCode();
                if (responseCode == 200) {
                    response = getBytesFromHttpInputStream(conn.getInputStream(), maxMessageLength);
                }
            } catch (Exception ex) {
            }

        } catch (Exception e) {
        }
        return response;
    }

    private static byte[] httpGet(String serviceUrl, Map<String, String> valueMap) {
        byte[] response = null;
        try {
            URL url = new URL(serviceUrl + "?" + getRequestQueryData(null, valueMap));
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.connect();


            try {

                int responseCode = conn.getResponseCode();
                if (responseCode == 200) {
                    response = getBytesFromHttpInputStream(conn.getInputStream(), maxMessageLength);
                }
            } catch (Exception ex) {
            }

        } catch (Exception e) {
        }
        return response;
    }

    private static String getRequestQueryData(InputStream dataIs, Map<String, String> paramMap) {
        byte[] data = null;
        try {
            if (dataIs != null) {
                data = getBytesFromInputStream(dataIs, maxMessageLength);
            }
        } catch (IOException ex) {
        }
        StringBuilder b = new StringBuilder();
        Iterator<String> keys = paramMap.keySet().iterator();
        while (keys.hasNext()) {
            String key = keys.next();
            b.append(encodeURIComponent(key)).append("=").append(encodeURIComponent(paramMap.get(key)));
            if (keys.hasNext()) {
                b.append("&");
            } else {
                if (data != null) {
                    b.append("&");
                    b.append("data=").append(encodeURIComponent(b64Eencode(data)));
                }
            }
        }
        return b.toString();
    }

    private static byte[] getBytesFromInputStream(InputStream is, int maxLen)
            throws IOException {

        byte[] bytes = null;
        try {
            // Get the size of the file
            long length = is.available();

            if (length > maxLen) {
                return null;
            }

            // Create the byte array to hold the data
            bytes = new byte[(int) length];

            // Read in the bytes
            int offset = 0;
            int numRead = 0;
            while (offset < bytes.length
                    && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
                offset += numRead;
            }

            // Ensure all the bytes have been read in
            if (offset < bytes.length) {
                throw new IOException("Could not completely read file ");
            }
        } catch (Exception ex) {
        } finally {
            is.close();
        }


        // Close the input stream and return bytes
        return bytes;
    }

    private static byte[] getBytesFromHttpInputStream(InputStream is, int maxLen)
            throws IOException {

        byte[] bytes = null;
        // create tempFile;
        String fName = String.valueOf(rng.nextLong()).replaceAll("-", "a") + ".tmp";
        File resultFile = new File(getfileNameString(tempFileLocation, fName));

        // Store result in tempprary file
        BufferedInputStream bufIn = new BufferedInputStream(is);
        try {

            FileOutputStream fos = new FileOutputStream(resultFile);
            byte[] b = new byte[100];
            for (;;) {
                int len = bufIn.read(b);
                if (len == -1) {
                    break;
                } else {
                    fos.write(b, 0, len);
                }
            }
            fos.close();
        } catch (Exception ex) {
            return null;
        } finally {
            bufIn.close();
        }
        //Read result from file
        long length = resultFile.length();
        if (length < maxLen) {
            bytes = readBinaryFile(resultFile);
        }
        resultFile.delete();

        return bytes;
    }

    /**
     * Decodes the passed UTF-8 String using an algorithm that's compatible with
     * JavaScript's
     * <code>decodeURIComponent</code> function. Returns
     * <code>null</code> if the String is
     * <code>null</code>.
     *
     * @param s The UTF-8 encoded String to be decoded
     * @return the decoded String
     */
    private static String decodeURIComponent(String s) {
        if (s == null) {
            return null;
        }

        String result = null;

        try {
            result = URLDecoder.decode(s, "UTF-8");
        } // This exception should never occur.
        catch (UnsupportedEncodingException e) {
            result = s;
        }

        return result;
    }

    /**
     * Encodes the passed String as UTF-8 using an algorithm that's compatible
     * with JavaScript's
     * <code>encodeURIComponent</code> function. Returns
     * <code>null</code> if the String is
     * <code>null</code>.
     *
     * @param s The String to be encoded
     * @return the encoded String
     */
    private static String encodeURIComponent(String s) {
        String result = null;

        try {
            result = URLEncoder.encode(s, "UTF-8").replaceAll("\\+", "%20").replaceAll("\\%21", "!").replaceAll("\\%27", "'").replaceAll("\\%28", "(").replaceAll("\\%29", ")").replaceAll("\\%7E", "~");
        } // This exception should never occur.
        catch (UnsupportedEncodingException e) {
            result = s;
        }

        return result;
    }
    /*
     * Base 64 encoder and decoder
     */
    // Mapping table from 6-bit nibbles to Base64 characters.
    private static char[] map1 = new char[64];

    static {
        int i = 0;
        for (char c = 'A'; c <= 'Z'; c++) {
            map1[i++] = c;
        }
        for (char c = 'a'; c <= 'z'; c++) {
            map1[i++] = c;
        }
        for (char c = '0'; c <= '9'; c++) {
            map1[i++] = c;
        }
        map1[i++] = '+';
        map1[i++] = '/';
    }
    // Mapping table from Base64 characters to 6-bit nibbles.
    private static byte[] map2 = new byte[128];

    static {
        for (int i = 0; i < map2.length; i++) {
            map2[i] = -1;
        }
        for (int i = 0; i < 64; i++) {
            map2[map1[i]] = (byte) i;
        }
    }

    /**
     * Encodes a byte array into Base64 format. No blanks or line breaks are
     * inserted in the output.
     *
     * @param in An array containing the data bytes to be encoded.
     * @return A String containing the Base64 encoded data.
     */
    private static String b64Eencode(byte[] in) {
        int iOff = 0;
        int iLen = in.length;

        int oDataLen = (iLen * 4 + 2) / 3;       // output length without padding
        int oLen = ((iLen + 2) / 3) * 4;         // output length including padding
        char[] out = new char[oLen];
        int ip = iOff;
        int iEnd = iOff + iLen;
        int op = 0;
        while (ip < iEnd) {
            int i0 = in[ip++] & 0xff;
            int i1 = ip < iEnd ? in[ip++] & 0xff : 0;
            int i2 = ip < iEnd ? in[ip++] & 0xff : 0;
            int o0 = i0 >>> 2;
            int o1 = ((i0 & 3) << 4) | (i1 >>> 4);
            int o2 = ((i1 & 0xf) << 2) | (i2 >>> 6);
            int o3 = i2 & 0x3F;
            out[op++] = map1[o0];
            out[op++] = map1[o1];
            out[op] = op < oDataLen ? map1[o2] : '=';
            op++;
            out[op] = op < oDataLen ? map1[o3] : '=';
            op++;
        }
        return String.valueOf(out);
    }

    /**
     * Decodes a byte array from Base64 format. No blanks or line breaks are
     * allowed within the Base64 encoded input data.
     *
     * @param s A Base64 String to be decoded.
     * @return An array containing the decoded data bytes.
     * @throws IllegalArgumentException If the input is not valid Base64 encoded
     * data.
     */
    private static byte[] b64Decode(String s) {
        char[] in = s.toCharArray();
        int iOff = 0;
        int iLen = in.length;

        if (iLen % 4 != 0) {
            throw new IllegalArgumentException("Length of Base64 encoded input string is not a multiple of 4.");
        }
        while (iLen > 0 && in[iOff + iLen - 1] == '=') {
            iLen--;
        }
        int oLen = (iLen * 3) / 4;
        byte[] out = new byte[oLen];
        int ip = iOff;
        int iEnd = iOff + iLen;
        int op = 0;
        while (ip < iEnd) {
            int i0 = in[ip++];
            int i1 = in[ip++];
            int i2 = ip < iEnd ? in[ip++] : 'A';
            int i3 = ip < iEnd ? in[ip++] : 'A';
            if (i0 > 127 || i1 > 127 || i2 > 127 || i3 > 127) {
                throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
            }
            int b0 = map2[i0];
            int b1 = map2[i1];
            int b2 = map2[i2];
            int b3 = map2[i3];
            if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0) {
                throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
            }
            int o0 = (b0 << 2) | (b1 >>> 4);
            int o1 = ((b1 & 0xf) << 4) | (b2 >>> 2);
            int o2 = ((b2 & 3) << 6) | b3;
            out[op++] = (byte) o0;
            if (op < oLen) {
                out[op++] = (byte) o1;
            }
            if (op < oLen) {
                out[op++] = (byte) o2;
            }
        }
        return out;
    }

    private static void trustAllCAs() {
        try {
            /*
             *  fix for
             *    Exception in thread "main" javax.net.ssl.SSLHandshakeException:
             *       sun.security.validator.ValidatorException:
             *           PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException:
             *               unable to find valid certification path to requested target
             */
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
            };

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception ex) {
            LOG.warning(ex.getMessage());
        }
    }

    private static String getfileNameString(String path, String fileName) {
        if (path == null || fileName == null) {
            return "";
        }

        String name = fileName;
        if (fileName.endsWith("/")) {
            name = fileName.substring(0, fileName.length() - 1);
        }

        if (path.endsWith("/")) {
            return path + name;
        }

        return path + "/" + name;
    }

    /**
     * creates a directory with the specified name if that directory does not
     * already exists.
     *
     * @param dirName The name of the directory
     * @return true if the directory exists or was created successfully, false
     * otherwise.
     */
    private static boolean createDir(String dirName) {
        if (dirName.endsWith("/")) {
            dirName = dirName.substring(0, dirName.length() - 1);
        }
        File dir = new File(dirName);
        if (!dir.exists()) {
            return dir.mkdirs();
        }
        return true;
    }

    private static byte[] readBinaryFile(File file) {
        List inp = new LinkedList<Byte>();
        try {
            FileInputStream fi = new FileInputStream(file);
            while (fi.available() > 0) {
                inp.add(fi.read());
            }
        } catch (IOException ex) {
            return new byte[0];
        }
        byte[] b = new byte[inp.size()];
        int i = 0;
        for (Object o : inp) {
            int val = (Integer) o;
            b[i++] = (byte) val;
        }
        return b;
    }
}
