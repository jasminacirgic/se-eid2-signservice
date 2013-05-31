<%-- 
    Document   : docframe
    Created on : Oct 20, 2012, 4:24:17 AM
    Author     : stefan
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Document iFrame</title>
        <script type="text/javascript" charset="UTF-8" src="script/jquery.js"></script>
        <link rel="stylesheet" type="text/css" href="script/spstylesheet.css">
        <script type="text/javascript" charset="UTF-8">
            var servletUrl = "SpServlet";
            var id;
            var parameter;

            $(document).ready(function() {
                id = getQueryVariable("id"); 
                parameter = getQueryVariable("parameter"); 
                $("#buttonDiv").hide();
                if (parameter=="direct"){
                    getDocument();
                } else {
                    $("#buttonDiv").show();
                }
            });
            
            function getDocument(){
                window.location = servletUrl+"?action="+id;                 
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

        </script>
    </head>
    <body>
        <div id="buttonDiv" >
            <input type="button" onclick="getDocument()" value="Show Document" />
        </div>
    </body>
</html>
