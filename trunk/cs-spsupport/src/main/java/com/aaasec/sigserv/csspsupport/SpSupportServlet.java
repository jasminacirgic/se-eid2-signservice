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
package com.aaasec.sigserv.csspsupport;

import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.XhtmlForm;
import com.aaasec.sigserv.csspapp.models.ServiceStatus;
import com.aaasec.sigserv.csspapp.models.SignSession;
import com.aaasec.sigserv.csspsupport.context.SpSuppContextParams;
import com.aaasec.sigserv.csspsupport.models.SupportConfig;
import com.aaasec.sigserv.csspsupport.models.SupportModel;
import com.aaasec.sigserv.csspsupport.signtask.SigSessionFactory;
import com.aaasec.sigserv.csspsupport.sigrequest.SigRequest;
import com.aaasec.sigserv.csspsupport.sigrequest.SigResponse;
import com.aaasec.sigserv.csspsupport.testcases.TestRequests;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Support service servlet. This servlet is used for the legacy JAVA API.
 */
public class SpSupportServlet extends HttpServlet {

    private SupportConfig conf;
    private SupportModel model;
    private Map<String, SignSession> signTaskMap = new HashMap<String, SignSession>();
    private long signSessionMaxAge;
    private String sigTempDir;

    @Override
    public void init(ServletConfig config) throws ServletException {
        model = SpSuppContextParams.getModel();
        conf = SpSuppContextParams.getConf();
        sigTempDir = SpSuppContextParams.getSigTempDir();
        signSessionMaxAge = SpSuppContextParams.getSignSessionMaxAge();
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

        // Get request parameters
        response.setContentType("text/html;charset=UTF-8");
        String action = request.getParameter("action");
        String idAttr = getParameter(request, "idattr");
        String id = getParameter(request, "id");
        String idp = getParameter(request, "idp");
        String returnUrl = getParameter(request, "returnurl");
        String spEntityId = getParameter(request, "sp");
        String sigMessage = getParameter(request, "signmess");
        String data = getParameter(request, "data");
        String parameter = getParameter(request, "parameter");
        String sigAlgo = getParameter(request, "sigalgo");
        String ref = getParameter(request, "ref");
        String testCase = getParameter(request, "testcase");

        if (action == null) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            respond(response, "");
            return;
        }

        if (action.equals("sign")) {
            byte[] docBytes = Base64Coder.decode(data);
            byte[] signMessBytes = Base64Coder.decode(sigMessage);
            cleanupSignTasks();
            SignSession signTask = SigSessionFactory.getSigSessionTask(docBytes, sigTempDir);
            if (signTask == null) {
                respond(response, "Illegal document type <a href='index.jsp'>back</a>");
                return;
            }
            signTask.setDocument(docBytes);
            signTask.setSignerAttribute(idAttr);
            signTask.setSignerId(id);
            signTask.setIdpEntityId(idp);
            signTask.setReturnUrl(returnUrl);
            signTask.setSpEntityId(spEntityId);
            signTask.setSignMessage(signMessBytes);
            signTask.setReqSigAlgorithm(sigAlgo);
            signTask.setLastUsed(System.currentTimeMillis());
            String prepareSignRedirect = prepareSignRedirect(request, response, signTask);

            respond(response, prepareSignRedirect);
            return;
        }

        if (action.equalsIgnoreCase("response")) {
            response.setContentType("application/json;charset=UTF-8");
            byte[] sigResponse = Base64Coder.decode(data);
            cleanupSignTasks();
            ServiceStatus status = SigResponse.processSignResponse(sigResponse, signTaskMap);
            String jsonStatus = model.getGson().toJson(status);
            respond(response, jsonStatus);
            return;
        }

        if (action.equalsIgnoreCase("getsigned")) {
            if (signTaskMap.containsKey(id)) {
                SignSession signTask = signTaskMap.get(id);
                ServiceStatus status = signTask.getStatus();
                if (status.signedDocValid) {
                    byte[] signedXml = signTask.getSignedDoc();
                    if (parameter.equalsIgnoreCase("b64")) {
                        switch (signTask.getDocumentType()) {
                            case XML:
                                respond(response, String.valueOf(Base64Coder.encode(signedXml)));
                                return;
                            case PDF:
                                respond(response, String.valueOf(Base64Coder.encode(FileOps.readBinaryFile(signTask.getSigFile()))));
                        }
                    }
                    if (parameter.equalsIgnoreCase("binary")) {
                        response.setContentType(signTask.getDocumentType().getMimeType());
                        switch (signTask.getDocumentType()) {
                            case XML:
                                respond(response, new String(signedXml, Charset.forName("UTF-8")));
                                return;
                            case PDF:
                                FileInputStream fis = new FileInputStream(signTask.getSigFile());
                                ServletOutputStream output = response.getOutputStream();
//                                response.setHeader("Content-Disposition", "attachment; filename="
//                                        + "signedPdf.pdf");

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
                    }
                }
            }
        }

        if (action.equalsIgnoreCase("testcase")) {

            if (data.length() == 0) {
                respond(response, "No document <a href='index.jsp'>back</a>");
                return;
            }

            byte[] docBytes = Base64Coder.decode(data);
            byte[] signMessBytes = Base64Coder.decode(sigMessage);
            cleanupSignTasks();
            SignSession signTask = SigSessionFactory.getSigSessionTask(docBytes, sigTempDir);
            if (signTask == null) {
                respond(response, "Illegal document type <a href='index.jsp'>back</a>");
                return;
            }
            signTask.setDocument(docBytes);
            signTask.setSignerAttribute(idAttr);
            signTask.setSignerId(id);
            signTask.setIdpEntityId(idp);
            signTask.setSpEntityId(spEntityId);
            signTask.setReturnUrl(returnUrl);
            signTask.setSignMessage(signMessBytes);
            signTask.setReqSigAlgorithm(sigAlgo);
            signTask.setLastUsed(System.currentTimeMillis());

            if (testCase.equalsIgnoreCase("replay")) {
                if (!signTaskMap.containsKey(ref)) {
                    respond(response, "No request <a href='index.jsp'>back</a>");
                    return;
                }
                SignSession referenceTask = signTaskMap.get(ref);
                signTask.setSignRequestID(referenceTask.getSignRequestID());
            }
            if (testCase.equalsIgnoreCase("resign")) {
                if (signTaskMap.containsKey(ref)) {
                    switch (signTask.getDocumentType()) {
                        case XML:
                            signTask.setDocument(signTaskMap.get(ref).getSignedDoc());
                            break;
                        case PDF:
                            signTask.setDocument(signTaskMap.get(ref).getSigFile());
                    }
                }
            }

            String prepareSignRedirect = testCaseRedirect(request, response, signTask, testCase);
            respond(response, prepareSignRedirect);
            return;
        }
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

    private String getParameter(HttpServletRequest req, String parameter) {
        String value = req.getParameter(parameter);
        return value == null ? "" : value;
    }

    private void respond(HttpServletResponse response, String responseData) throws IOException {
        PrintWriter writer = response.getWriter();
        writer.write(responseData);
        writer.close();
    }

    private String prepareSignRedirect(HttpServletRequest request,
            HttpServletResponse response, SignSession signTask) {

        String csServiceUrl = conf.getSigServiceRequestUrl();
        byte[] sigRequest = new byte[]{};
        String nonce = "";

        try {
            nonce = signTask.getSignRequestID();
            sigRequest = SigRequest.getRequest(model, signTask);
            signTaskMap.put(nonce, signTask);
        } catch (Exception ex) {
        }

        return XhtmlForm.getSignXhtmlForm(
                XhtmlForm.Type.SIG_REQUEST_FORM,
                csServiceUrl,
                sigRequest,
                nonce);
    }

    private String testCaseRedirect(HttpServletRequest request,
            HttpServletResponse response, SignSession signTask, String testcase) {

        String csServiceUrl = conf.getSigServiceRequestUrl();
        byte[] sigRequest = null;
        String nonce = "";

        nonce = signTask.getSignRequestID();
        if (testcase.equalsIgnoreCase("resign")) {
            sigRequest = SigRequest.getRequest(model, signTask);
        } else {
            sigRequest = TestRequests.getTestCaseRequest(model, signTask, testcase);
        }
        if (!testcase.equalsIgnoreCase("replay")) {
            signTaskMap.put(nonce, signTask);
        }

        return XhtmlForm.getSignXhtmlForm(
                XhtmlForm.Type.SIG_REQUEST_FORM,
                csServiceUrl,
                sigRequest,
                nonce);
    }

    private void cleanupSignTasks() {
        List<String> deleteKeys = new ArrayList<String>();
        Iterator<String> keys = signTaskMap.keySet().iterator();
        while (keys.hasNext()) {
            String key = keys.next();
            SignSession sigTask = signTaskMap.get(key);
            long lastUsed = sigTask.getLastUsed();
            if (System.currentTimeMillis() > (lastUsed + signSessionMaxAge)) {
                deleteKeys.add(key);
            }
        }
        if (!deleteKeys.isEmpty()) {
            for (String key : deleteKeys) {
                SignSession taskToDelete = signTaskMap.get(key);
                taskToDelete.clear();
                signTaskMap.remove(key);
            }
        }
    }
}
