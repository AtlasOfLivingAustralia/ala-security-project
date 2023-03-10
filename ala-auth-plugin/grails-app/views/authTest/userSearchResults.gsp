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
<h1>User Details Search Results</h1>
<g:if test="${user}">
    <table class="table table-striped table-bordered">
        <tr>
            <td>User ID</td>
            <td>${user.userId}</td>
        </tr>
        <tr>
            <td>User name</td>
            <td>${user.userName}</td>
        </tr>

        <tr>
            <td>Display Name</td>
            <td>${user.displayName}</td>
        </tr>

    </table>
</g:if>
<g:else>
    <div class="alert alert-error">
        User not found
    </div>
</g:else>

</body>
</html>