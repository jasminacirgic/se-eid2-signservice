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
package com.aaasec.sigserv.csspserver;

import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.csspapp.SignSupportAPI;
import com.aaasec.sigserv.csspserver.iaik.AuthContextQCStatement;
import com.aaasec.sigserv.csspserver.iaik.AuthContextQCStatementOld;
import com.aaasec.sigserv.csspserver.iaik.PdsQCStatement;
import com.aaasec.sigserv.csspserver.models.RequestModel;
import com.aaasec.sigserv.csspserver.models.SpConfig;
import com.aaasec.sigserv.csspserver.models.SpModel;
import com.aaasec.sigserv.csspserver.models.SpSession;
import com.aaasec.sigserv.csspserver.test.TestCases;
import com.aaasec.sigserv.csspserver.testidp.TestIdentities;
import com.aaasec.sigserv.csspserver.utility.RequestModelFactory;
import com.aaasec.sigserv.csspserver.utility.SpServerLogic;
import com.google.gson.Gson;
import iaik.x509.extensions.qualified.structures.QCStatement;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.fileupload.servlet.ServletFileUpload;

/**
 * Service provider web application servlet.
 */
public class SpServlet extends HttpServlet implements Constants {

    private RequestModelFactory reqFactory;
    private static Map<BigInteger, SpSession> sessionMap = new HashMap<BigInteger, SpSession>();
    private static Gson gson;
    private static SpConfig conf;
    private static long day = 1000 * 60 * 60 * 24;
    private static final Logger LOG = Logger.getLogger(SpServlet.class.getName());

    @Override
    public void init(ServletConfig config) throws ServletException {
        reqFactory = new RequestModelFactory();
        conf = SpModel.getConf();
        gson = SpModel.getGson();
        SignSupportAPI.setSpSupportUrl(conf.getSupportServiceUrl());
        SignSupportAPI.setMaxMessageLength(conf.getMaxMessageLength());
        SignSupportAPI.setValidationServiceUrl(conf.getValidationServiceUrl());
        SignSupportAPI.setValidationPolicy(conf.getValidationPolicy());
        SignSupportAPI.setTempFileLocation(FileOps.getfileNameString(SpModel.getDataDir(), "httpTemp"));

        //Register private QCStatements
        QCStatement.register(PdsQCStatement.statementID, PdsQCStatement.class);
        QCStatement.register(AuthContextQCStatement.statementID, AuthContextQCStatement.class);
        QCStatement.register(AuthContextQCStatementOld.statementID, AuthContextQCStatementOld.class);
//        X509Extensions.register(AuthContextExtension.extensionOid, AuthContextExtension.class);
    }

    /**
     * Processes requests for both HTTP
     * <code>GET</code> and
     * <code>POST</code> methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        request.setCharacterEncoding("UTF-8");
        response.setCharacterEncoding("UTF-8");
        response.setContentType("text/html;charset=UTF-8");
        response.setHeader("Cache-Control", "no-cache");

        SpSession session = getSession(request, response);

        RequestModel req = reqFactory.getRequestModel(request, session);
        AuthData authdata = req.getAuthData();

        // Supporting devmode login
        if (SpModel.isDevmode()) {
            authdata = TestIdentities.getTestID(request, req);
            req.setAuthData(authdata);
            if (authdata.getAuthType().length() == 0) {
                authdata.setAuthType("devlogin");
            }
            session.setIdpEntityId(authdata.getIdpEntityID());
            session.setSignerAttribute(RequestModelFactory.getAttrOidString(authdata.getIdAttribute()));
            session.setSignerId(authdata.getId());
        }

        //Terminate if no valid request data
        if (req == null) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            response.getWriter().write("");
            return;
        }

        // Handle form post from web page
        boolean isMultipart = ServletFileUpload.isMultipartContent(request);
        if (isMultipart) {
            response.getWriter().write(SpServerLogic.processFileUpload(request, response, req));
            return;
        }

        // Handle auth data request 
        if (req.getAction().equals("authdata")) {
            response.setContentType("application/json");
            response.setHeader("Cache-Control", "no-cache");
            response.getWriter().write(gson.toJson(authdata));
            return;
        }

        // Get list of serverstored xml documents
        if (req.getAction().equals("doclist")) {
            response.setContentType("application/json");
            response.getWriter().write(SpServerLogic.getDocList());
            return;
        }

        // Provide info about the session for logout handling
        if (req.getAction().equals("logout")) {
            response.setContentType("application/json");
            Logout lo = new Logout();
            lo.authType = (request.getAuthType() == null) ? "" : request.getAuthType();
            lo.devmode = String.valueOf(SpModel.isDevmode());
            response.getWriter().write(gson.toJson(lo));
            return;
        }

        // Respons to a client alive check to test if the server session is alive
        if (req.getAction().equals("alive")) {
            response.setContentType("application/json");
            response.getWriter().write("[]");
            return;
        }


        // Handle sign request and return Xhtml form with post data to the signature server
        if (req.getAction().equals("sign")) {
            boolean addSignMessage = (req.getParameter().equals("message"));
            String xhtml = SpServerLogic.prepareSignRedirect(req, addSignMessage);
            response.getWriter().write(xhtml);
            return;
        }

        // Get status data about the current session
        if (req.getAction().equals("status")) {
            response.setContentType("application/json");
            response.getWriter().write(gson.toJson(session.getStatus()));
            return;
        }

        // Handle a declined sign request
        if (req.getAction().equals("declined")) {
            if (SpModel.isDevmode()) {
                response.sendRedirect("index.jsp?declined=true");
                return;
            }
            response.sendRedirect("https://eid2cssp.3xasecurity.com/sign/index.jsp?declined=true");
            return;
        }

        // Return Request and response data as a file.
        if (req.getAction().equalsIgnoreCase("getReqRes")) {
            response.setContentType("text/xml;charset=UTF-8");
            byte[] data = TestCases.getRawData(req);
            BufferedInputStream fis = new BufferedInputStream(new ByteArrayInputStream(data));
            ServletOutputStream output = response.getOutputStream();
            if (req.getParameter().equalsIgnoreCase("download")) {
                response.setHeader("Content-Disposition", "attachment; filename="
                        + req.getId()+".xml");
            }

            int readBytes = 0;
            byte[] buffer = new byte[10000];
            while ((readBytes = fis.read(buffer, 0, 10000)) != -1) {
                output.write(buffer, 0, readBytes);
            }
            output.flush();
            output.close();
            fis.close();
            return;
        }

        // Return the signed document
        if (req.getAction().equalsIgnoreCase("getSignedDoc") || req.getAction().equalsIgnoreCase("getUnsignedDoc")) {
            // If the request if for a plaintext document, or only if the document has a valid signature
            if (session.getStatus().signedDocValid || req.getAction().equalsIgnoreCase("getUnsignedDoc")) {
                response.setContentType(session.getDocumentType().getMimeType());
                switch (session.getDocumentType()) {
                    case XML:
                        response.getWriter().write(new String(session.getSignedDoc(), Charset.forName("UTF-8")));
                        return;
                    case PDF:
                        File docFile = session.getDocumentFile();
                        if (req.getAction().equalsIgnoreCase("getSignedDoc") && session.getStatus().signedDocValid) {
                            docFile = session.getSigFile();
                        }
                        FileInputStream fis = new FileInputStream(docFile);
                        ServletOutputStream output = response.getOutputStream();
                        if (req.getParameter().equalsIgnoreCase("download")) {
                            response.setHeader("Content-Disposition", "attachment; filename="
                                    + "signedPdf.pdf");
                        }

                        int readBytes = 0;
                        byte[] buffer = new byte[10000];
                        while ((readBytes = fis.read(buffer, 0, 10000)) != -1) {
                            output.write(buffer, 0, readBytes);
                        }
                        output.flush();
                        output.close();
                        fis.close();
                        return;
                }
                return;
            } else {
                if (SpModel.isDevmode()) {
                    response.sendRedirect("index.jsp");
                    return;
                }
                response.sendRedirect("https://eid2cssp.3xasecurity.com/sign/index.jsp");
                return;
            }
        }

        // Process a sign response from the signature server
        if (req.getSigResponse().length() > 0) {
            try {
                byte[] sigResponse = Base64Coder.decode(req.getSigResponse().trim());

                // Handle response
                SpServerLogic.completeSignedDoc(sigResponse, req);

            } catch (Exception ex) {
            }
            if (SpModel.isDevmode()) {
                response.sendRedirect("index.jsp");
                return;
            }
            response.sendRedirect("https://eid2cssp.3xasecurity.com/sign/index.jsp");
            return;
        }


        // Handle testcases
        if (req.getAction().equals("test")) {
            boolean addSignMessage = (req.getParameter().equals("message"));
            String xhtml = TestCases.prepareTestRedirect(request, response, req, addSignMessage);
            respond(response, xhtml);
            return;
        }

        // Get test data for display such as request data, response data, certificates etc.
        if (req.getAction().equals("info")) {
            switch (session.getDocumentType()) {
                case PDF:
                    File returnFile = null;
                    if (req.getId().equalsIgnoreCase("document")) {
                        respond(response, getDocIframe("getUnsignedDoc", needPdfDownloadButton(request)));
                    }
                    if (req.getId().equalsIgnoreCase("formSigDoc")) {
                        respond(response, getDocIframe("getSignedDoc", needPdfDownloadButton(request)));
                    }
                    respond(response, TestCases.getTestData(req));
                    return;
                default:
                    respond(response, TestCases.getTestData(req));
                    return;
            }
        }

        if (req.getAction().equals("verify")) {
            response.setContentType("text/xml;charset=UTF-8");
            String sigVerifyReport = TestCases.getTestData(req);
            if (sigVerifyReport != null) {
                respond(response, sigVerifyReport);
                return;
            }
        }

        nullResponse(response);
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP
     * <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP
     * <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

    private String getDocIframe(String type, boolean button) {
        StringBuilder b = new StringBuilder();
        b.append("<iframe src=\"");
        b.append("docframe.jsp").append("?id=").append(type);
        b.append("&parameter=").append(button ? "button" : "direct");
        b.append("\" frameborder=\"0\" width=\"100%\" height=\"800\"/>");
        return b.toString();
    }

    private static void respond(HttpServletResponse response, String responseData) {
        try {
            response.getWriter().write(responseData);
            response.getWriter().close();
        } catch (IOException ex) {
            Logger.getLogger(SpServlet.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void nullResponse(HttpServletResponse response) {
        try {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            response.getWriter().write("");
            response.getWriter().close();
        } catch (IOException ex) {
            Logger.getLogger(SpServlet.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static SpSession getSession(HttpServletRequest request, HttpServletResponse response) {
        BigInteger sessionID = new BigInteger(32, new Random(System.currentTimeMillis()));
        Cookie[] cookies = request.getCookies();
        try {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("SigSpSession")) {
                    sessionID = new BigInteger(cookie.getValue());
                }
            }
        } catch (Exception ex) {
        }
        response.addCookie(new Cookie("SigSpSession", sessionID.toString()));
        return getSessionFromID(sessionID);
    }

    private static SpSession getSessionFromID(BigInteger sessionID) {
        SpSession session = null;
        List<BigInteger> removeList = new ArrayList<BigInteger>();
        Set<BigInteger> idSet = sessionMap.keySet();
        for (BigInteger id : idSet) {
            SpSession storedSession = sessionMap.get(id);
            long lastUse = storedSession.getLastUsed();
            if ((lastUse + day) < System.currentTimeMillis()) {
                removeList.add(id);
                continue;
            }
            if (id.equals(sessionID)) {
                storedSession.setLastUsed(System.currentTimeMillis());
                session = storedSession;
            }
        }
        //cleanup
        for (BigInteger id : removeList) {
            if (sessionMap.containsKey(id)) {
                SpSession deleteSession = sessionMap.get(id);
                deleteSession.clear();
                sessionMap.remove(id);
            }
        }

        if (session == null) {
            session = new SpSession(sessionID, FileOps.getfileNameString(SpModel.getDataDir(), "sigTemp"));
            session.setLastUsed(System.currentTimeMillis());
            sessionMap.put(sessionID, session);
        }
        return session;
    }

    private static boolean needPdfDownloadButton(HttpServletRequest request) {
        boolean button = true;
        String userAgent = request.getHeader("user-agent");
        for (String[] keyArray : PDF_VIEW_USER_AGENT_KEYS) {
            boolean setMatch = true;
            for (String key : keyArray) {
                if (userAgent.indexOf(key) < 0) {
                    setMatch = false;
                }
            }
            if (setMatch) {
                return false;
            }
        }
        return button;
    }

    class Logout {

        String authType = "", devmode = "";

        public Logout() {
        }
    }
}
