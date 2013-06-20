

function validateSignature(){
    clearSigResult();
    var reqUrl = servletUrl+"?action=verify";
    $.ajax({
        type:'GET',
        url: reqUrl,
        cache: false,
        dataType:'xml',
        success: signatureResult,
        error: function(xhr, error){
            console.debug(xhr);
            console.debug(error);
        }
    });
}

/**
 * Clears previous signature result information from the web page
 */
function clearSigResult(){
    //cleanup
    $("#svResultArea").hide();
    $("#svResultHead").empty();
    $("#svResultTable").empty();
    $("#svCertArea").hide();
    $("#svCertHead").empty();
    $("#svCertTable").empty();    
}

/**
 * Displays signature result information on the web page based on the signature
 * validation result XML data
 */
function signatureResult(xml){
    docr="";
    sigr="";
    certr="";
    signatures =0;
    validSignatures=0;
    var parsed=0;

    //doc context
    $(xml).find("SignedDocumentValidation").each(function(){
        parseDoc(this);
        parsed=1;
    });
    if (parsed==0){
        $(xml).find("tslt\\:SignedDocumentValidation").each(function(){
            parseDoc(this);
        });        
    }
    
    // display result;
    var goodBad;
    var okIcon = "";
    if (validSignatures>0){
        goodBad = "goodBig";
        okIcon = '<img style="margin-right: 15px" src="img/Ok-icon.png" height="32" alt="OK"/>';
    } else {
        goodBad = "errorBig";
        okIcon = '<img style="margin-right: 15px" src="img/Nok-icon.png" height="25" alt="Not OK"/>';
    }
    var headString = "<h2>Signature Validation Result</h2>";
    if (validSignatures==1){
        headString+= '<p class="goodBig">'+okIcon+'1 valid signature (out of '+signatures;
    } else {
        headString+= '<p class="'+goodBad+'">'+okIcon+validSignatures+' valid signatures (out of '+signatures;        
    }
    headString+=")</p>";
    
    $("#svResultHead").append(headString);
    $("#svResultTable").append(docr);
    $("#svResultTable").append(sigr);

    $("#svCertHead").append("Certificate information");
    
    $("#svCertTable").append(certr);
    svShowErrors();
    svShowDetails();
    $("#svResultArea").show(500);
    svShowCerts();
}

/**
 * This function is part of the XML signature validation report display
 */
function parseDoc(doc){
    //Document properties
    //docr+=docRow(2,"attr",h3("Document"),'<a href="docs/'+$(doc).find("documentName").text()+'">'+$(doc).find("documentName").text()+'</a>');
    docr+=docRow(2,"attr",h3("Document"),$(doc).find("documentName").text());
    docr+=docRow(2,"attr","Document type",$(doc).attr("documentType"));
    var policyName = $(doc).find("policyName").text();
    var policyInfo='<i>No information about the policy "'+policyName +'" is available<i>';
    $(doc).find("policyInformation").each(function(){
        policyInfo = $(doc).find("policyInformation").text();
    });
    
    // Validation policy 
    docr+=docRow(3,"attr","Validation Policy",policyName,policyInfo );
    $(doc).find("signatureValidation").each(function(){
        parseSig(this);
    });
}

/**
 * This function is part of the XML signature validation report display
 */
function parseSig(sig){
    //found signature
    signatures+=1;
    var signName = $(sig).attr("signatureName");
    sigr+=docRow(2,"normal",str("Signature (name)"), str(signName));
    //Signature valid
    var validity = $(sig).find("validationResult").text();
    if (validity=="valid"){
        validSignatures+=1;
        sigr+=docRow(2,"good","Signature validity", validity)
    } else {
        sigr+=docRow(2,"error","Signature validity", validity)        
    }
    //Error messages
    $(sig).find("validationErrorMessages").each(function(){
        $(this).find("message").each(function(){
            var messType = $(this).attr("type");
            if (messType=="error"){
                sigr+=docRowB("errorMess","",messType,$(this).text());                
            } else {
                sigr+=docRowB("warn","",messType,$(this).text());                                
            }
        });
    });
    //EU Qualifications;
    $(sig).find("euQualifications").each(function(){
        sigr+=docRow(2,"attr","EU Qualifications",$(this).text());                
    });
    
    //Signature Algorithms
    $(sig).find("signatureAlgorithms").each(function(){
        var first = "Signature algorithms";
        $(this).find("algorithm").each(function(){
            sigr+=docRow(3,"verbAttr",first,$(this).attr("OID"),$(this).text()); 
            first="";
        });
    });
    

    //Signing time
    $(sig).find("claimedSigningTime").each(function(){
        sigr+=docRow(2,"verbAttr","Claimed signing time", $(this).text().replace("T", "&nbsp;&nbsp;&nbsp;"));
    });
                        
    //time stamp
    $(sig).find("timeStamp").each(function(){
        var tsError=0;
        var tsTime = $(this).find("time").text()
        var errorMsg="";
        $(this).find("statusMessages").each(function(){
            //sigr+=docRow(2,"good","","Found message");                            
            $(this).find("message").each(function(){
                var messType = $(this).attr("type");
                if (messType=="error"){
                    tsError = 256;
                    errorMsg+=docRowB("errorMess","",messType,$(this).text());                
                } else {
                    tsError +=1;
                    errorMsg+=docRowB("warnMess","",messType,$(this).text());                
                }                
            });            
        });
        if (tsError ==0){
            sigr+=docRow(2,"good","Timestamp", tsTime.replace("T", "&nbsp;&nbsp;&nbsp;"));            
        } else {
            if (tsError >255){
                sigr+=docRow(2,"error","Timestamp", tsTime.replace("T", "&nbsp;&nbsp;&nbsp;"));
            } else {
                sigr+=docRow(2,"attr","Timestamp", tsTime.replace("T", "&nbsp;&nbsp;&nbsp;"));                            
            }
        }
        sigr+=errorMsg;
    });
            
    //Subject Name
    $(sig).find("signerDistinguishedName").each(function(){
        sigr+=emptyRow();
        var first = b("Signer identity");
        $(this).find("attributeValue").each(function(){
            sigr+=docRow(3,"prop",first,$(this).attr("type"), $(this).text());
            first="";
        });
    });
    
    //Certificate info
    var parsed=0;
    $(sig).find("signerCertificateInfo").each(function(){
        certr+=docRow(2,"normal"," ", "");                
        certr+=docRow(2,"normal",str("Signature (name)"), str(signName));
        certr+=docRow(1,"normal",b('<I>Signer Certificate</I>'));
        parseCertInfo(this);
        parsed=1;
    }); 
    if (parsed==0){
        certr+=docRow(2,"normal"," ", "");                
        certr+=docRow(2,"normal",str("Signature (name)"), str(signName));
        certr+=docRow(2,"error",b('<I>Signer Certificate</I>'),"Certificate path could not be built to a trusted authority");        
    }
}

/**
 * This function is part of the XML signature validation report display
 */
function parseCertInfo(certInfo){
    //Validity
    $(certInfo).find("certificate:first").each(function(){
        //Certificate status
        $(this).find("certificateStatus").each(function(){
            //Valid status
            var status = $(this).find("validityStatus").text();
            if (status=="valid"){
                certr+=docRow(2,"good","Revocation status",status);                            
            }else {
                certr+=docRow(2,"error","Revocation status",status);            
            }
            var first = "Revocation source";
            $(this).find("validationSource").each(function(){
                certr+=docRow(3,"attr",first,$(this).attr("type"), $(this).text());
                first="";
            });
        });
    
        certr+=docRow(3,"attr","Validity","Not before",$(this).find("notValidBefore").text().replace("T", "&nbsp;&nbsp;&nbsp;"));
        certr+=docRow(3,"attr","","Not After",$(this).find("notValidAfter").text().replace("T", "&nbsp;&nbsp;&nbsp;"));
    
        //Subject Name
        $(this).find("subjectName").each(function(){
            certr+=emptyRow();
            var first = b("Subject name");
            $(this).find("attributeValue").each(function(){
                certr+=docRow(3,"prop",first,$(this).attr("type"), $(this).text());
                first="";
            });
        });
    
        //Issuer Name
        $(this).find("issuerName").each(function(){
            certr+=emptyRow();
            var first = b("Issuer name");
            $(this).find("attributeValue").each(function(){
                certr+=docRow(3,"prop",first,$(this).attr("type"), $(this).text());
                first="";
            });        
        });
        
        //Public Key Algorithm
        $(this).find("publicKeyAlgorithm").each(function(){
            certr+=docRow(3,"attr","Public Key",$(this).attr("keyLength")+" bit", $(this).text());            
        });
    
        //Extensions
        $(this).find("certificateExtensions").each(function(){
            certr+=emptyRow();
            certr+=docRow(1,"normal",'<I><U>Certificate extensions</U></I>');
            parseExtensions(this);
        });
    });
    
    
    //IssuerCertificate info
    $(certInfo).find("issuerCertificateInfo:first").each(function(){
        certr+=docRow(1,"normal", "");
        certr+=docRow(1,"normal",b('<I>Issuer Certificate</I>'));
        parseCertInfo(this);
    });

}


/**
 * This function is part of the XML signature validation report display
 */
function parseExtensions (extensions){
    $(extensions).find("certificateExtension").each(function(){
        certr+=docRow(2,"attr",$(this).attr("name"), "Critical="+$(this).attr("critical"));
        $(this).find("parameter").each(function(){
            certr+=docRow(3,"prop","",$(this).attr("type"), $(this).text());
        });
    });
}


/**
 * Switches on or off eror details display
 */
function svShowErrors(){
    if ($("#svShowError").attr('checked')){
        $("#svResultTable tr.errorRow").show();
    } else {
        $("#svResultTable tr.errorRow").hide();
    }
}

/**
 * Switches on or off detailed information display
 */
function svShowDetails(){
    if ($("#svShowDetails").attr('checked')){
        $("#svResultTable tr.verboseRow").show();
    } else {
        $("#svResultTable tr.verboseRow").hide();
    }
}

/**
 * Switches on or off certificate information display
 */
function svShowCerts(){
    if ($("#svShowCert").attr('checked')){
        $("#svCertArea").fadeIn(500);
    } else {
        $("#svCertArea").fadeOut(500);
    }    
}
