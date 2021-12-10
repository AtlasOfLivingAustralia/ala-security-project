package au.org.ala.ws.security;

public class AnnotatedMethodController {

    @RequireAuth
    def securedAction() {}
    def publicAction() {}
}
