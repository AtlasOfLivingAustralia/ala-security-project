<%@ page contentType="text/html;charset=UTF-8" %>
<!DOCTYPE html>
<html>
    <head>
        <meta name="layout" content="main"/>
        <title>Test page for auth</title>
        <style type="text/css" media="screen">
        </style>
    </head>

    <body class="nav-datasets">
        <h1>User Details Search</h1>

        <g:form controller="authTest" action="userSearchResults">
            <div class="form-horizontal">
                <div class="control-group">
                    <label class="control-label" for="userId">User Id</label>
                    <div class="controls">
                        <input type="text" id="userId" name="userId" placeholder="User ID" />
                    </div>
                </div>
                <div class="control-group">
                    <div class="controls">
                        <g:submitButton name="btnSubmit" value="Search" class="btn btn-primary" />
                    </div>
                </div>
            </div>
        </g:form>
    </body>
</html>