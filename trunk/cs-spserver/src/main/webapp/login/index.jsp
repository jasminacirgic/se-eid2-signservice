<%-- 
    Document   : index
    Created on : Feb 10, 2012, 11:11:32 AM
    Author     : stefan
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>EID 2.0 Central Signing Test Service - Login page</title>

        <script type="text/javascript" src="https://eid2.3xasecurity.com/disco/jquery-1.8.3.js"></script>
        <script type="text/javascript" src="https://eid2.3xasecurity.com/disco/jquery_eid2Disco.js"></script>
        <script type="text/javascript" src="https://eid2.3xasecurity.com/disco/jQuery_cookie-1.3.js"></script>
        <script type="text/javascript" charset="UTF-8" src="loginscript.js"></script>
        <link rel="stylesheet" type="text/css" href="https://eid2.3xasecurity.com/disco/eid2Disco.css">
        <link rel="stylesheet" type="text/css" href="loginstylesheet.css">
    </head>

    <body>
        <div class="bodyFrame" align="center">
            <div class="workAreaFrame" align="left">
                <div class="top">
                    <div class="rightTop">
                        <img src="img/eid20.png" height="35" alt="EID 2.0"/></a>
                    </div>
                    <div class="leftTop">
                        <img src="img/sp-logga.png" height="65" alt="SP-Myndigheten"/>
                    </div>
                    <div class="centerTop">
                        <h1>SP-Myndigheten</h1>
                        <h2>Login to EID 2.0 Signature Service</h2>
                    </div>
                </div>

                <div class="inpbar" style="min-height: 20px">
                    <div style="background-color: inherit">
                        <table style="background-color: inherit; width: 100%">
                            <tr style="background-color: inherit">
                                <td><b>Login with Swedish test e-identification</b>&nbsp;&nbsp;<span id="idpDiscoLoginButton"></span></td>
                                <td style="text-align: right" id="discoType"></td>
                            </tr>
                        </table>
<!--                        <b id="userInfo" style="margin-right: 15px"></b>
                        <span>... eller med&nbsp;</span><a class="inpbarlink" href="https://eid2cssp.3xasecurity.com/sign/">Central anvisning</a>-->
                    </div>
                </div>
                <div id="eid2Disco" style="background-color: #ffffff"></div>
                <br />

                <div style="margin-top: 10px;background-color: #f8f8f8">
                    <table id="refTable">
                        <tbody>
                            <tr><td colspan="2"><u><Strong class="colored">Related links and resources</Strong></u></td></tr>
                        <tr><td><a href="https://eid2cssp.3xasecurity.com/login/index.jsp?idp=https://idp.test.eid2.se/idp/shibboleth">SSO login</a></td>
                            <td class="prop">via EID Testbädd Referens-IDP</td></tr>
                        <tr><td><a href="http://aaa-sec.com/eid2/sigsupport">Documentation</a></td>
                            <td class="prop">XML Schema, protocol specification, source link, etc</td></tr>
                        <tr><td><a href="https://docs.eid2.se/">docs.eid2.se</a></td>
                            <td class="prop">Wiki - Testbädden för Eid 2.0</td></tr>
                        <tr><td><a href="https://eid2cssp.3xasecurity.com/Shibboleth.sso/Session">SAML Session</a></td>
                            <td class="prop">Status for current SAML SP session</td></tr>
                        </tbody>
                    </table>            
                </div>
                <div style="margin-top: 10px;background-color: #ffffff">
                    <p>This service is deployed according to the following basic model:</p>
                    <a style="margin-left: 30px"class="image" href="https://eid2.3xasecurity.com/docs/DeploymentEid2.pdf"><img src="img/eid2SpService.png" width="600" alt="3xA Security"/></a>                
                </div>
            </div>
        </div>
    </body>
</html>
