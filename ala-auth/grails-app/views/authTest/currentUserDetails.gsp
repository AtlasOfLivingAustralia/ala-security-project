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

<body class="content">

<h1>Current User</h1>
<table class="table table-bordered table-striped">
    <tr>
        <td>
            User Id
        </td>
        <td>
            ${authService.userId}
        </td>
    </tr>
    <tr>
        <td>
            Display Name
        </td>
        <td>
            ${authService.displayName}
        </td>
    </tr>
    <tr>
        <td>
            Email
        </td>
        <td>
            ${authService.email}
        </td>
    </tr>
    <tr>
        <td>
            Current User Obj
        </td>
        <td>
            ${authService.userDetails()}
        </td>
    </tr>

</table>
</body>
</html>