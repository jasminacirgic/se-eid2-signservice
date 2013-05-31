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
package com.aaasec.sigserv.sigserver;

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.cssigapp.SignatureCreationHandler;
import com.aaasec.sigserv.cssigapp.models.RequestModel;
import com.aaasec.sigserv.cssigapp.models.SigServerModel;
import com.google.gson.Gson;
import java.io.IOException;
import java.security.Security;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet for signature creation.
 */
public class SignatureServlet extends HttpServlet implements Constants {

    private RequestModelFactory reqFactory;
    private SigServerModel model;
    private Gson gson;
    private SignatureCreationHandler serverBack;

    @Override
    public void init(ServletConfig config) throws ServletException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        reqFactory = new RequestModelFactory();
        model = new SigServerModel();
        gson = model.getGson();
        serverBack = new SignatureCreationHandler(model);
    }

    /** 
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code> methods.
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        request.setCharacterEncoding("UTF-8");

        RequestModel req = reqFactory.getRequestModel(request);
        AuthData authdata = req.getAuthData();
        // Supporting devmode login
        if (model.isDevmode()) {
            authdata = TestSigIdentities.getTestID(request, req);
            req.setAuthData(authdata);
            if (authdata.getAuthType().length() == 0) {
                authdata.setAuthType("devlogin");
            }
        }

        if (req.getAction().equals("sign")) {
            response.setContentType("text/html");
            String signID = req.getId();
            String signResponse = serverBack.createSignature(signID, authdata);
//            response.getWriter().write(prepareSigResponse(signResponse));
            response.getWriter().write(signResponse);
            return;
        }


    }

    /**
     * Gets the integer representation of an input string.
     * @param intString input string
     * @return integer representation of the input string, returns 0 of the string is not a legitimate integer string.
     */
    private int getInt(String intString) {
        int val = 0;
        try {
            val = Integer.parseInt(intString);
        } catch (Exception ex) {
        }
        return val;
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /** 
     * Handles the HTTP <code>GET</code> method.
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
     * Handles the HTTP <code>POST</code> method.
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
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

    private String prepareSigResponse(String sigRequest) {
        StringBuilder b = new StringBuilder();
        b.append("<html>");
        b.append("<head>");
        b.append("<title>Servlet SigServlet</title>");
        b.append("</head>");
        b.append("<body>");
        b.append("<h1>SigServlet response</h1>");
        b.append("<b>Data:</b>");
        b.append("<xmp>").append(sigRequest).append("</xmp>");
        b.append("<p><a href='http://localhost:8080/CSspServer/index.jsp'>Back to Service Provider</a></p>");
        b.append("</body>");
        b.append("</html>");
        return b.toString();
    }
}
