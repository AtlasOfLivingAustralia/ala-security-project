<%@ page contentType="text/html;charset=UTF-8" %>
<!DOCTYPE html>
<html>
    <head>
        <meta name="layout" content="main"/>
        <title>Test page for auth</title>
        <style type="text/css" media="screen">
        </style>
    </head>

    <body class="content">

        <g:if test="${flash.message}">
            <div class="alert alert-error">
                ${flash.message}
            </div>
        </g:if>

        <h1>AUTH test pages</h1>
        <table class="table table-bordered table-striped">
            <tr>
                <td>
                    <a class="btn" href="${createLink(controller: 'authTest', action:'userList')}">User List</a>
                </td>
                <td>
                    Dumps the entire user list
                </td>
            </tr>
            <tr>
                <td>
                    <a class="btn" href="${createLink(controller: 'authTest', action:'userDetailsSearch')}">User Details Search</a>
                </td>
                <td>
                    Search for user details
                </td>
            </tr>
            <tr>
                <td>
                    <a class="btn" href="${createLink(controller: 'authTest', action:'currentUserDetails')}">Current User</a>
                </td>
                <td>
                    Test AuthService methods that return info about current user
                </td>
            </tr>
            <tr>
                <td>
                    <div>
                        <hf:loginLogout cssClass="btn"/> ${request.userPrincipal}
                    </div>
                </td>
                <td>
                    Test the Header/Footer logout button
                </td>
            </tr>


        </table>
    </body>
</html>