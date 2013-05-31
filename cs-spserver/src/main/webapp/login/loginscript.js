var feedSource = "source=https://eid2.3xasecurity.com/Shibboleth.sso/DiscoFeed";
//var jsonpDisco="https://ds.test.eid2.se/JsonDiscoFeed/";
var jsonpDisco="https://jsonpdisco.3xasecurity.com/";
//var devIdpUrl = "https://eid2cssp.3xasecurity.com/sign/devIdp.jsp";
var devIdpUrl = "../devIdp.jsp";
var entityID=new Array();
var displayName=new Array();
var devmode=false;

/**
 * Execute on page load
 */
$(document).ready(function() {
    if (getQueryVariable("devmode")=="true"){
        devmode=true;
    }
    if (getQueryVariable("logout")=="true"){
        $(".information").hide();
//        alert("Du har blivit utloggad. För säkrast möjliga utloggning, stäng ner din webbläsare");
        window.location="https://eid2cssp.3xasecurity.com/login/";
    }
    var preIdp = getQueryVariable("idp");
    if (preIdp.length >0){
        idpLogin(preIdp);
    }

    if (devmode){
        getDevDisco();
    } else {
        getDiscoUIComponents();
        $.eid2Disco({
            lang: "sv",
            discodiv:"eid2Disco",
            success : function(entityId){
                idpLogin(entityId);
            },
            error : function(message){
                alert(message);
            }
        });
    }

    if ($.cookie("showInfo")=="1"){
        $("#infoBox").prop("checked", true);
        $(".information").show();
    } else {
        $(".information").hide();        
    }
});



/**
 * Generate Discovery mode UI elements
 */
function getDiscoUIComponents(){
    var discoType = $.cookie('discotype');
    var idpDisco = (discoType!=null && discoType=="idpdisco");
    var intDisco = !idpDisco;
    var idpDiscoRadio = $('<input>').attr('type','radio').attr('name','discotype').attr('checked',idpDisco).click(function(){
        if ($(this).attr('checked')){
            $.cookie('discotype','idpdisco',{
                expires:200
            });
            updatedDiscoMode(false);
        }
    });
    var intDiscoRadio = $('<input>').attr('type','radio').attr('name','discotype').attr('checked',intDisco).click(function(){
        if ($(this).attr('checked')){
            $.cookie('discotype','intdisco',{
                expires:200
            });
            updatedDiscoMode(true);            
        }
    });
    
    //Create central discovery button
    var idpDiscoButton = $('<input>').attr('type','button').attr('value','Login').click(function(){
        var seed=Math.floor(Math.random()*100000001)
        window.location="https://eid2cssp.3xasecurity.com/sign/index.jsp?nonce="+seed;        
    });
    
    // Add UI elements
    $("#discoType").append("Central Anvisning").append(idpDiscoRadio).append("&nbsp;&nbsp;&nbsp;Integrerad Anvisning").append(intDiscoRadio);
    $("#idpDiscoLoginButton").html(idpDiscoButton);
    
    updatedDiscoMode(intDisco);
}

function updatedDiscoMode(intDisco){
    if (intDisco){
        $("#eid2Disco").show();
        $("#idpDiscoLoginButton").hide();
    } else {
        $("#eid2Disco").hide();
        $("#idpDiscoLoginButton").show();
    }    
}


/**
 * Builds the idP select box for devmode testing 
 */
function getDevDisco(){
    $('<input>').attr("type","button").attr("value","Devlogin").click(function(){
        devLogin();
    }).appendTo("#idpDiscoLoginButton");
}

/**
 * Executes login to the service using the selected IdP for user authentication
 */
function idpLogin(idp){
    window.location = "https://eid2cssp.3xasecurity.com/Shibboleth.sso/Login?entityID="
    + encodeURIComponent(idp) + "&target="+encodeURIComponent("https://eid2cssp.3xasecurity.com/sign/");
}

/**
 * Executes login using devmode IdP
 */
function devLogin(){
    window.location=devIdpUrl;
}

/**
 * Show information about available IdPs and the current session if the
 * show info select box is checked, else hide this information
 */
function showInfo(){
    if ($("#infoBox").attr('checked')){
        $(".information").fadeIn(500);
        $.cookie("showInfo", "1");
    } else {
        $(".information").fadeOut(500);
        $.cookie("showInfo", "0");
    }    
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

