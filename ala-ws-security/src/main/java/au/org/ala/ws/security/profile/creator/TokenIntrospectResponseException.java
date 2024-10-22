package au.org.ala.ws.security.profile.creator;

public class TokenIntrospectResponseException extends Throwable {
    public TokenIntrospectResponseException(String message) {
        super("Token introspection response error: " + message);
    }
}
