package au.org.ala.ws.tokens

import com.nimbusds.oauth2.sdk.ParseException
import com.nimbusds.oauth2.sdk.TokenErrorResponse
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser
import com.nimbusds.openid.connect.sdk.token.OIDCTokens
import groovy.util.logging.Slf4j
import org.pac4j.core.exception.TechnicalException
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.credentials.OidcCredentials

@Slf4j
class TokenClient {

    private OidcConfiguration oidcConfiguration

    TokenClient(OidcConfiguration oidcConfiguration) {
        this.oidcConfiguration = oidcConfiguration
    }


    // TODO Change this to not retuen OidcCredentials any more because
    // OidcCredentials doesn't store a parsed AccessToken object
    OIDCTokens executeTokenRequest(TokenRequest request) throws IOException, ParseException {
        def tokenHttpRequest = request.toHTTPRequest()
        if (oidcConfiguration) {
            oidcConfiguration.configureHttpRequest(tokenHttpRequest)
        }

        def httpResponse = tokenHttpRequest.send()
        log.debug("Token response: status={}, content={}", httpResponse.getStatusCode(),
                httpResponse.getContent())

        def response = OIDCTokenResponseParser.parse(httpResponse)
        if (response instanceof TokenErrorResponse) {
            def errorObject = ((TokenErrorResponse) response).getErrorObject()
            throw new TechnicalException("Bad token response, error=" + errorObject.getCode() + "," +
                    " description=" + errorObject.getDescription())
        }
        log.debug("Token response successful")
        def tokenSuccessResponse = (OIDCTokenResponse) response

//        def credentials = new OidcCredentials()
        return tokenSuccessResponse.getOIDCTokens()
//        credentials.setAccessTokenObject(oidcTokens.getAccessToken())
//        credentials.setRefreshTokenObject(oidcTokens.getRefreshToken())
//        if (oidcTokens.getIDToken() != null) {
//            credentials.setIdToken(oidcTokens.getIDToken().getParsedString())
////            credentials.setIdToken(oidcTokens.getIDToken().serialize())
//        }
//        return credentials
    }

}
