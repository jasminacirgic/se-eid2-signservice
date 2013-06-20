<%-- 
    Document   : index
    Created on : Aug 4, 2008, 10:33:51 PM
    Author     : nbuser
--%>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
    "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>EID 2.0 Central Signing Test Service</title>

        <script type="text/javascript" charset="UTF-8" src="script/jquery.js"></script>
        <script type="text/javascript" charset="UTF-8" src="script/jquery.form.js"></script>
        <script type="text/javascript" charset="UTF-8" src="script/jquery_cookie.js"></script>
        <script type="text/javascript" charset="UTF-8" src="script/spmainscript.js"></script>
        <script type="text/javascript" charset="UTF-8" src="script/sigVerify.js"></script>
        <link rel="stylesheet" type="text/css" href="script/spstylesheet.css">
    </head>

    <body>
        <div class="top">
            <div class="rightTop">
                <img src="img/eid20.png" height="35" alt="EID 2.0"/></a>
            </div>
            <div class="leftTop">
                <img src="img/sp-logga.png" height="65" alt="SP-Myndigheten"/></a>
            </div>
            <div class="centerTop">
                <h1>SP-Myndigheten</h1>
                <h2>EID 2.0 Signature Service</h2>
            </div>
        </div>

        <div id="authArea">
            <div class="inpbar" style="min-height: 25px">
                <div id="authInfo" style="background-color: inherit; float: right;min-height: inherit"></div>
                <div id="userInfo" style="background-color: inherit; min-height: inherit"></div>                
            </div>
            <div id="authTableArea">
                <div style="float: right"><a onclick="clearStatus()" href="/login/">Login page</a></div>
                <table id="authTable"></table></div>
        </div>

        <div id="selectArea">
            <p>This is a test service for signing documents using a central signing server.</p>
            <p>
                Signing mode:&nbsp;&nbsp;
                <select onchange="selectSignMode()" id="mode-select">
                    <option>Sign with accept dialogue</option>
                    <option>No sign accept dialogue</option>
                </select>
                <br />
                Signing Algorithm: &nbsp;&nbsp;
                RSA&nbsp;<input type="radio" name="sigAlgo" id="algoRSA" onclick="setSigAlgo(0)">&nbsp;&nbsp;&nbsp;
                ECDSA&nbsp;<input type="radio" name="sigAlgo" id="algoECDSA" onclick="setSigAlgo(1)">&nbsp;&nbsp;&nbsp;
            </p>

            <div>
                <form id="uploadFileForm"  enctype="multipart/form-data" action="SpServlet" method="post">
                    <table>
                        <tbody>
                            <tr><td><b><u>Provide XML document</u></b></td>
                                <td><input type="checkbox" id="serverDocs" onclick="useServerDocs()"/>
                                    Select test document on server</td>
                            </tr>
                            <tr id="serverFileRow">
                                <td class="b">Select XML File on Server </td>
                                <td><select onchange="selectServerDoc()" name="xmlName" id="doc-select"></select></td>
                            </tr>
                            <tr id="uploadFileRow">
                                <td class="b">Upload XML File to sign </td><td><input type="file" name="sigfile" id="signedFileInput" size="34"></td>
                            </tr>
                            <tr>
                                <td><input type="submit" onclick="clearXmlTbsArea()" value="Get document" /></td>
                            </tr>
                        </tbody>
                    </table>
                </form>
                <%--<br/>
                <input type="button" value="Verify Signature"onclick="validateSignature()"/>--%>
            </div>
        </div>
        <br/>
        <div id="resultArea">            
            <div class="inpbar2" style="min-height: 26px; vertical-align: bottom">
                <div style="float: right; background-color: inherit;max-height: 25px">
                    <span id="resultCheckBoxes">
                        <input type="checkbox" id="testCasesCb" onclick="showTestCases()"/>
                        &nbsp;Test cases&nbsp;&nbsp;
                        <input type="checkbox" id="detailsCb" onclick="showDetails()"/>
                        &nbsp;Show details&nbsp;&nbsp;
                    </span>
                    <input type="button" onclick="clearStatus()" value="Clear"/>                    
                </div>
                <span>Document:</span>
                <span id="xmlFileName"></span>
                <span id="signbutton" >
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    <input type="button" onclick="signData()" value="Accept and Sign">
                </span>
            </div>
            <div id="testVectors" style="float: right">
                <table>
                    <tr><td colespan="3"><b>Test cases</b></td></tr>
                    <tr>
                        <td>Repeat</td>
                        <td><button class="test" onclick="test('reSign')">Sign again</button></td>
                        <td><button class="test" onclick="test('replay')">Replay request</button></td>
                    </tr>
                    <tr>
                        <td>Request signature</td>
                        <td><button class="test" onclick="test('badReqSig')">Bad signature</button></td>
                        <td><button class="test" onclick="test('unknownRequester')">Unknown requester</button></td>
                    </tr>
                    <tr>
                        <td>Request time</td>
                        <td><button class="test" onclick="test('oldReq')">Old request</button></td>
                        <td><button class="test" onclick="test('predatedReq')">Postdated</button></td>
                    </tr>
                </table>
            </div>
            <div style="color: #000000" id="resultTable"></div>
            <!--<br />
            <button id="verifySignatureButton" onclick="validateSignature()">Verify Signature</button>-->
            <div><br /></div>

            <div id="resultFrame">
                <div id="dataSelectors" style="height: 25px">
                    <button id="sigRequest" onclick="showDetailsByButtonOrder(0)" >Request</button>
                    &nbsp;&nbsp;&nbsp;
                    <button id="sigResponse" onclick="showDetailsByButtonOrder(1)" >Response</button>
                    &nbsp;&nbsp;&nbsp;
                    <button id="sigCert" onclick="showDetailsByButtonOrder(2)" >Certificate</button>

                    <select id="certSelect" onchange="showDetailsByButtonOrder(2)"></select>
                    &nbsp;&nbsp;&nbsp;
                    &nbsp;&nbsp;&nbsp;
                    <button id="orgDoc" onclick="showDetailsByButtonOrder(3)" >Original Document</button>
                    &nbsp;&nbsp;&nbsp;
                    <button id="formSigDoc" onclick="showDetailsByButtonOrder(4)">Signed Document</button>
                    &nbsp;&nbsp;&nbsp;
                </div>
                <div id="resultData" style="overflow: scroll"></div>
            </div>
            <div id="svResultArea">            
                <div class="inpbar">Show
                    <input class="space" type="checkbox" id="svShowDetails" onclick="svShowDetails()"/>Details
                    <input class="space" type="checkbox" id="svShowError" onclick="svShowErrors()"/>Error messages
                    <input class="space" type="checkbox" id="svShowCert" onclick="svShowCerts()"/>Certificate information
                </div>
                <div id="svResultHead"></div>
                <table id="svResultTable"></table>
                <br/>
                <%--
                <input id="showButton" type="button" value="Show certificate info"/>
                <input id="hideButton" type="button" value="Hide certificate info"/>
                --%>
                <div id="svCertArea">                
                    <h2 id="svCertHead"></h2>
                    <br/>
                    <table id="svCertTable"></table>
                </div>
            </div>


        </div>

    </body>
</html>
