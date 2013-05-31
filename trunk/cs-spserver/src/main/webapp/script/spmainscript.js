var servletUrl = "SpServlet";
var loginUrl = "https://eid2cssp.3xasecurity.com/login/";
var sessionCookie = "SigSpSession";
var serverDocsCookie = "serverDocs";
var selectedDocCookie = "serverDocIdx";
var testCasesCookie = "testCases";
var detailsOptionCookie = "detailsOption";
var detailsCookie = "details";
var selectedModeCookie = "signMode";
var selectedAlgoCookie = "sigAlgo";
var authData;
var okIcn = "<img src='img/Ok-icon.png' height='20' alt='Valid'/>";
var nokIcn = "<img src='img/Nok-icon.png' height='20' alt='Valid'/>";
var devmode = false;
var status="init";
var documentName="";
var respSigValid=false;
var signedDocValid=false;
var validResponse=false;
var responseCode ="";
var responseMessage="";
var signingTime="";
var userId=null;
var pathLen=0;
var signCommand;

/**
 * Execute on page load
 */
$(document).ready(function() {
    $("#resultArea").hide();
    $("#certArea").hide();
    $("#authArea").hide();
    $("#selectArea").hide();
    $("#serverDocs").removeAttr('checked');
    $("#serverFileRow").hide();
    $("#svResultArea").hide();
    $('#uploadFileForm').ajaxForm(function(resp) { 
        if (resp=="OK"){
            getStatus();
        } else {
            clearStatus();
        }
    });
    $("#pdf-field").change(function(){
        $("#signedFileInput").replaceWith($("#signedFileInput").clone(true));
        $('#signedFileInput').val("");
    });
    if (getQueryVariable("declined")=="true"){
        $.cookie(sessionCookie,null);
        alert("Signing request declined");
        window.location="index.jsp";
    }
    aliveCheck();
    getAuthData();
    getDocList();
    getStatus();
    setSignedDocumentAref();
    signCommand="message"
    var selectedMode = $.cookie(selectedModeCookie)!=null? parseInt($.cookie(selectedModeCookie)):0;
    $('#mode-select option')[selectedMode].selected = true;
    if (selectedMode==1){
        signCommand="noconf"
    }
    setPreSelectedAlgo();
});



/**
 * Checks that the current server session is alive
 * if not, the session cookie is cleared and the user returned to the login page
 */
function aliveCheck(){
    $.ajax({
        url: servletUrl,
        data: {
            "action":"alive"
        },
        dataType:"json",
        success: function(data){},
        error: function(){
            alert("Your session has timed out\nReturning to login page");
            $.cookie("SigSpSession",null);
            window.location=loginUrl;
        }
    });
}


/**
 * Gets information about the authenticated user and dispalys a welcome message
 * asnd a logout button
 */
function getAuthData(){
    var userBar;
    var authInfo;
    var at;
    
    $("#userInfo").empty();
    $("#authTable").empty();
    $.getJSON(servletUrl+"?action=authdata", function(data){
        if (data.authType =="devlogin"){
            window.location="login/index.jsp?devmode=true";
            //            window.location="https://eid2cssp.3xasecurity.com/sign/login/index.jsp?devmode=true";
            return;            
        }
        if (data.authType.length==0){
            window.location="login/index.jsp";
            return;            
        }
        
        userBar = "User: <strong class='colorSpace'>"+data.remoteUser+"</strong>";
        authInfo='<input type="checkbox" id="checkAuthInfo" onclick="showAuthInfo()"/>User authentication details';
        authInfo+='&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;';
        authInfo+='<input type="button" onclick="logout()" value="Logout">'
        $("#userInfo").append(userBar);
        $("#authInfo").append(authInfo);

        //Authentication Context
        at= docRow(3,"attr",b("Authentication context"),"AuthType",data.authType);
            
        $.each(data.context, function(i,attr){
            at+=docRow(3,"attr","",attr[1], attr[2]);                
        });

        //User Attributes
        var first = b("User attributes");
        $.each(data.attribute, function(i,attr){
            at+=docRow(3,"prop",first,attr[1], attr[2]);                
            first="";
        });
            
        $("#authTable").append(at);
        $("#authTableArea").hide();
        $("#authArea").show();
        
    });
}

/**
 * Gets the list of test documents available on the server 
 */
function getDocList(){
    $.getJSON(servletUrl+'?action=doclist', function(data) {
        $("#doc-select").empty();
        $("<option></option>").html("--Select--").appendTo("#doc-select");    
        $.each(data, function(i,name){
            $("<option></option>").html(name).appendTo("#doc-select");            
        });
        var selectedDoc =0;
        if (status!="init" && status !="response" && $.cookie(selectedDocCookie)!=null){
            selectedDoc = $.cookie(selectedDocCookie);
        }
        $('#doc-select option')[selectedDoc].selected = true;
    });
}

/**
 * Gets the current session state and adapts the page to the current state
 */
function getStatus(){
    $.getJSON(servletUrl+'?action=status', function(data) {
        status=data.status;
        documentName=data.documentName;
        respSigValid=data.respSigValid;
        signedDocValid=data.signedDocValid;
        validResponse=data.validResponse;
        responseCode =data.responseCode;
        responseMessage=data.responseMessage;
        signingTime = data.signingTime;
        userId = data.userId;
        pathLen = data.pathLen;
        
        //Resore cookie based settings
        $("#serverDocs").prop("checked", $.cookie(serverDocsCookie));
        $("#testCasesCb").prop("checked", $.cookie(testCasesCookie));
        $("#detailsCb").prop("checked", $.cookie(detailsCookie));
        var detailsOption = parseInt($.cookie(detailsOptionCookie));
        if (detailsOption == null){
            detailsOption=0;
        }
        useServerDocs();
        if ($("#testCasesCb").attr('checked')){
            $("#testVectors").show();
        } else {
            $("#testVectors").hide();
        }    
        if ($("#detailsCb").attr('checked')){
            $("#resultFrame").show();
        } else {
            $("#resultFrame").hide();
        }
        
        //If init status
        if (status=="init"){
            $("#selectArea").show();
            $("#resultArea").hide();
            $("#certArea").hide();
            return;
        }
        
        //If sign Accept status
        if (status=="accept"){
            $("#resultData").load(servletUrl+"?action=info&id=document",function(){
                displayStatus();
                $("#svResultArea").hide();
                $("#xmlFileName").append(documentName);
                $("#selectArea").show();
                $("#resultArea").show();
                $("#signbutton").show();
                $("#dataSelectors").hide();
                $("#testVectors").hide();
                $("#resultFrame").show();
                $("#resultCheckBoxes").hide();
            });
        }
        
        //Handle response status
        if (status=="response"){
            setCertSelectOptions();
            $("#resultData").load(servletUrl+"?action=info&id=request",function(){
                displayStatus();
                showDetailsByButtonOrder(detailsOption);
                $("#xmlFileName").append(documentName);
                $("#resultArea").show();
                $("#selectArea").hide();
                $("#signbutton").hide();
                $("#dataSelectors").show();
                if (!validResponse){
                    showSignTaskInfo('response','sigResponse');            
                } else {
                    validateSignature();
                }
            });
        }                
    });
    
}

/**
* Create the certificate display select options
*/
function setCertSelectOptions(){
    $("#certSelect").empty();
    $("<option></option>").html("User cert").appendTo("#certSelect");
    if (pathLen>1){
        $("<option></option>").html("CA cert").appendTo("#certSelect");        
    }
    if (pathLen>2){
        $("<option></option>").html("Root cert").appendTo("#certSelect");        
    }
}

/**
*Clears the state of the server serssion by deleting the session cookie and reload
*page state
*/
function clearStatus(){
    aliveCheck();
    $('#doc-select option')[0].selected = true;
    $.cookie(sessionCookie,null);
    getStatus();
}


function showDetailsByButtonOrder(order){
    switch(order){
        case 1:
            showSignTaskInfo('response','sigResponse');            
            break;
        case 2:
            showCert('sigCert');
            break;
        case 3:
            showSignTaskInfo('document','orgDoc');
            break;
        case 4:
            showSignTaskInfo('formSigDoc','formSigDoc');
            break;        
        default:
            showSignTaskInfo('request','sigRequest');
    }
    $.cookie(detailsOptionCookie,order);
}

/**
* Displays information about the signtask
* dataType is an identifier of the type of data to be displayed
* button is the id of the button pressed to show data
*/
function showSignTaskInfo(dataType, button){
    aliveCheck();
    if (status=="response"){        
        $("#resultData").load(servletUrl+"?action=info&id="+dataType,function(){});
        selectButton("dataSelectors",button);
    }
}

/**
 * Sets the hyperlink for downloading the signed document
 */
function setSignedDocumentAref(){
    $("#signedDocAref").append("<a href='"+servletUrl +"?action=getSignedDoc"+"'>Signed Document</a>");
}


/**
* Displays certificate information
* idx= The index of the certificate in the present certificate chain
* button = the id of the button pressed to show a certificate 
*/
function showCert(button){
    var idx = document.getElementById('certSelect').selectedIndex;
    aliveCheck();
    if (status=="response"){
        $("#resultData").load(servletUrl+"?action=info&id=certificate&parameter="+idx,function(){});        
        selectButton("dataSelectors",button);
    }            
}

/**
* Highlight a selected button within an identified parent element
* parent = the id of the parent element (typically a div)
* button = the id of the selected button
*/
function selectButton(parent, button){
    $("#"+ parent +" .selected").removeClass('selected');
    $("#"+button).addClass('selected');    
}

/**
* Displays status information about a signature action
*/
function displayStatus(){
    var at;
    var first;
    $("#resultTable").empty();
    if (status !="response"){
        return;            
    }        

    //Signature process (Whether the central signing action was successful)
    if (validResponse){
        at= docRow(3,"prop",b("Sign Status"),"Signature creation process",okIcn);        
    } else {
        at= docRow(3,"prop",b("Sign Status"),"Signature creation process",nokIcn);              
        at+= docRow(3,"errorMess","","Reason",responseMessage);              
    }
    
    //Response validity (Wether the signature on the resoonse was OK)
    if (respSigValid){
        at+= docRow(3,"prop","","Sign response signature",okIcn);        
    } else {
        at+= docRow(3,"prop","","Sign response signature",nokIcn);                
    }

    //Document signature validity (Whether the resutling signed document signature is valid)
    if (signedDocValid){
        at+= docRow(3,"prop","","Document signature",okIcn);  
        at+= docRow(3,"prop","","Signing time",signingTime);
        at+= docRow(3,"prop","","Signed document","<a href='"+servletUrl +"?action=getSignedDoc&parameter=download'>Get document</a>")
        at+= docRow(3,"prop","","Protocol elements","<a href='"+servletUrl +"?action=getReqRes&id=request'>Request</a>&nbsp;&nbsp;"+
            "<a href='"+servletUrl +"?action=getReqRes&id=response'>Response</a>&nbsp;&nbsp;"+
            "<a href='"+servletUrl +"?action=getReqRes&id=assertion'>Assertion</a>");
    } else {
        at+= docRow(3,"prop","","Document signature",nokIcn);                
    }    
    at+= docRow(2,"prop","&nbsp;","");                
    
    //    //Get user identity (Display user identity attributes
    //    first = b("Signer");
    //    $.each(userId , function(i,attr){
    //        at+= docRow(3,"attr",first,attr.name,attr.value);
    //        first="";
    //    });
    // Render result
    $("#resultTable").append(at);    
}

/**
* Logs out the user form the current service provided by this page
*/
function logout(){
    $.cookie(sessionCookie,null);
    $.ajax({
        url: servletUrl,
        data: {
            "action":"logout"
        },
        dataType:"json",
        success: function(data){
            if (data.devmode == "true"){
                window.location="login/index.jsp?devmode=true";
                return;
            }
            if (data.authType =="shibboleth"){
                window.location ="/Shibboleth.sso/LocLogout?return="+encodeURIComponent(loginUrl+"index.jsp?logout=true");
            } else {
                window.location=loginUrl;            
            }            
        },
        error: function(){
            $.cookie("SigSpSession",null);
            window.location=loginUrl;
        }
    });    
        
}

/**
* Clears data about the xml data for signing
*/
function clearXmlTbsArea(){
    aliveCheck();
    $("#xmlAreaSrc").empty();
    $("#xmlFileName").empty();
}

/*
* Initiates a request to sign the current data
* The response to this page reload is an XHTML page
* with a form containing the actual sign request
* and a Java script that sends the form data (request)
* to the signature service.
*/
function signData(){
    $.ajax({
        url: servletUrl,
        data: {
            "action":"alive"
        },
        dataType:"json",
        success: function(data){
            window.location=servletUrl+"?action=sign&parameter="+signCommand;
        },
        error: function(){
            alert("Your session has timed out\nReturning to login page");
            $.cookie("SigSpSession",null);
            window.location=loginUrl;
        }
    });
}

/**
* Initiates a test case sign request
* id = the identifier of the test case
*/
function test(id){
    $.ajax({
        url: servletUrl,
        data: {
            "action":"alive"
        },
        dataType:"json",
        success: function(data){
            window.location=servletUrl+"?action=test&id="+id+"&parameter="+signCommand;            
        },
        error: function(){
            alert("Your session has timed out\nReturning to login page");
            $.cookie("SigSpSession",null);
            window.location=loginUrl;
        }
    });
}

/**
* Returns the provided text surrounded with bold tags
*/
function b(txt){
    return "<b class='big'>"+txt+"</b>";
}

/**
* Returns the provided text surrounded with strong text tags
*/
function str(txt){
    return "<strong class='big'>"+txt+"</strong>";
}

/**
* Returns the provided text surrounded with heading 3 tags
*/
function h3(txt){
    return "<strong class='fat'>"+txt+"</h3>";
}

/**
* Returns a table row with appropriate html tags (3 column table)
* elements = the number of data elements in this table row (If less than 3 then the last column is padded with colspan)
* style = an identifier of the style of the row
* p1-p3 = the table data elements (null or absent if not present)
*/
function docRow (elements, style, p1,p2,p3){
    var tr = getTrClass(style);
    if (elements==1){
        return tr+'<td colspan="3" class="'+style+'">'+p1+"</td></tr>";
    }
    if (elements==2){
        return tr+"<td>"+p1+'</td><td  colspan="2" class="'+style+'">'+p2+"</td></tr>";
    }
    if (elements==3){
        return tr+"<td>"+p1+'</td><td class="'+style+'">'+p2+"</td><td>"+p3+"</td></tr>";
    }
    return "";
}

/**
* Returns a table row with 3 elements
*/
function docRowB (style, p1,p2,p3){
    return docRow(3,style,p1,p2,p3);
}

/**
* Returns the actual classNames used for various row styles in the docRow function
*/
function getTrClass (style){
    var tr = "<tr>";
    if (style == "errorMess" || style=="warnMess"){
        tr='<tr class="errorRow">';
        return tr;
    }
    if (style == "verbAttr"){
        tr='<tr class="verboseRow">';
        return tr;
    }
    return "<tr class=normRow>";    
}

/**
* Returns an empty table row
*/
function emptyRow(){
    return "<tr class=emptyRow><td>&nbsp</td></tr>";
}

/**
* Returns the value of the specified url query string found in the url used to load this page
*/
function getQueryVariable(variable) { 
    var query = window.location.search.substring(1); 
    var vars = query.split("&"); 
    for (var i=0;i<vars.length;i++) { 
        var pair = vars[i].split("="); 
        if (pair[0] == variable) { 
            return pair[1]; 
        } 
    }
    return "";
} 

/**
* Shows or hides the user authentication information table
* depending on whether the associated checkbox is checked.
*/
function showAuthInfo(){
    if ($("#checkAuthInfo").attr('checked')){
        $("#authTableArea").fadeIn(500);
    } else {
        $("#authTableArea").fadeOut(500);
    }    
}

/**
* Toggles diaplay of testcases
*/
function showTestCases(){
    if ($("#testCasesCb").attr('checked')){
        $("#testVectors").fadeIn(500);
        $.cookie(testCasesCookie,true);
    } else {
        $("#testVectors").fadeOut(500);
        $.cookie(testCasesCookie,null);
    }        
}

/**
* Toggles display of detailed information
*/
function showDetails(){
    if ($("#detailsCb").attr('checked')){
        $("#resultFrame").fadeIn(500);
        $.cookie(detailsCookie,true);
    } else {
        $("#resultFrame").fadeOut(500);
        $.cookie(detailsCookie,null);
    }
}


/**
* Shows or hides the server document list depending on whether
* the checkbox for using server documents is checked.
*/
function useServerDocs(){
    $("#signedFileInput").replaceWith($("#signedFileInput").clone(true));
    $('#signedFileInput').val("");
    //    $('#doc-select option')[0].selected = true;

    if ($("#serverDocs").attr('checked')){
        $("#serverFileRow").show();
        $("#uploadFileRow").hide();
        $.cookie(serverDocsCookie,true);
    } else {
        $("#uploadFileRow").show();
        $("#serverFileRow").hide();
        $.cookie(serverDocsCookie,null);
    }
}

function selectSignMode(){
    var modeIdx = document.getElementById('mode-select').selectedIndex;
    $.cookie(selectedModeCookie,modeIdx);
    
    if (modeIdx==0){
        signCommand="message"
    } else {
        signCommand="noconf"
    }    
}

/**
* Stores the server doc selection index in a cookie
*/
function selectServerDoc(){
    var docIdx = document.getElementById('doc-select').selectedIndex;
    $.cookie(selectedDocCookie,docIdx);
}

/**
 * Toggle selected Algorithm
 */
function setSigAlgo(idx){
    $.cookie(selectedAlgoCookie,idx);
}

function setPreSelectedAlgo(){
    var algoIdx=parseInt($.cookie(selectedAlgoCookie));    
    switch(algoIdx){
        case 0:
            $("#algoRSA").attr('checked','checked');
            break;
        case 1:
            $("#algoECDSA").attr('checked','checked');
            break;
        default:
            $("#algoRSA").attr('checked','checked');
    }
}
