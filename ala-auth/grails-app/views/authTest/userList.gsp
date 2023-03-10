<%
    def authService = applicationContext.authService
%>
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
<h1>AUTH User List</h1>
<div>
    <table class="table table-bordered table-striped table-condensed">
        <thead>
            <tr>
                <th>User Id</th>
                <th>User Name</th>
                <th>Display Name</th>
            </tr>
        </thead>
        <tbody>
            <g:each var="user" in="${authService.allUserNameList}">
                <tr>
                    <td>${user.userId}</td>
                    <td>${user.userName}</td>
                    <td>${user.displayName}</td>
                </tr>
            </g:each>
        </tbody>
    </table>
</div>
</body>
</html>