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

import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.csspserver.models.RequestModel;
import com.aaasec.sigserv.csspserver.models.SpSession;
import java.nio.charset.Charset;

/**
 * This is a mockup class for producing the signature request message for a given
 * instance of signing.
 */
public class SigRequestMessage {

    public static byte[] getMessage(RequestModel req) {
        SpSession session = req.getSession();
        AuthData authData = req.getAuthData();
        String signingInstanceNonce = session.getSignRequestID();
        String docName = session.getDocumentFile().getName();

        try {
            StringBuilder b = new StringBuilder();
            b.append("<img src='https://eid2cssp.3xasecurity.com/login/img/sp-logga.png' height='40'/>");
            b.append("<i>&nbsp;&nbsp;You are requested to sign the following document:</i><br/><br/>");
            b.append("<table class='messageTable'>");
            b.append("<tr><td><b>Document name</b></td><td style='color:#867300'>").append(docName).append("</td></tr>");
            b.append("<tr><td><b>Signer name</b></td><td style='color:#867300'>").append(authData.getRemoteUser()).append("</td></tr>");
            b.append("<tr><td><b>Signer ID</b></td><td style='color:#867300'>").append(authData.getIdAttribute())
                    .append(" = ").append(authData.getId()).append("</td></tr>");
            b.append("</table>");
            return encode(b.toString());
        } catch (Exception ex) {
        }

        return encode("Error when creating signmessage");
    }
    
    private static byte[] encode(String inpStr){
        return inpStr.getBytes(Charset.forName("UTF-8"));
    }
    
}
