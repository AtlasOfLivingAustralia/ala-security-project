package au.org.ala.ws.security.credentials;

import com.nimbusds.jwt.JWT;
import org.pac4j.core.credentials.TokenCredentials;

public class JwtCredentials extends TokenCredentials {

    private JWT jwtAccessToken;

    public JwtCredentials(String token, JWT jwtAccessToken) {
        super(token);
        this.jwtAccessToken = jwtAccessToken;
    }


    public JWT getJwtAccessToken() {
        return jwtAccessToken;
    }

    public void setJwtAccessToken(JWT jwtAccessToken) {
        this.jwtAccessToken = jwtAccessToken;
    }
}
