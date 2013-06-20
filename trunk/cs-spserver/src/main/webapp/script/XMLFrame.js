var baseUrl = "SpServlet?action=";

$(document).ready(function() {
    init();
});


function init(){
    var selected = getQueryVariable("selected");
    var seed=Math.floor(Math.random()*100000001)
    $.ajax({
        type:'GET',
        url: baseUrl+"loadxml&parameter="+selected+"&seed="+seed,
        dataType:'xml',
        success: function(xml){
            LoadXMLDom('XMLHolder',xml);
        },
        error: function(xhr, error){
        }
    });
}

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

