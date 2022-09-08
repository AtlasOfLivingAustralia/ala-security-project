package au.org.ala.ws.security.authenticator

import au.org.ala.ws.security.profile.AlaApiUserProfile
import com.nimbusds.common.contenttype.ContentType
import com.nimbusds.jose.shaded.json.JSONObject
import com.nimbusds.oauth2.sdk.ParseException
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.http.HTTPResponse
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.credentials.authenticator.Authenticator
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.util.CommonHelper
import org.pac4j.core.util.InitializableObject
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

@Component
@ConditionalOnProperty([ 'security.apikey.enabled', 'security.jwt.fallback-to-legacy-behaviour' ])
class AlaApiKeyAuthenticator extends InitializableObject implements Authenticator {

    @Value('security.apikey.check.serviceUrl')
    String apiKeyUri

    @Value('security.apikey.userdetails.serviceUrl')
    String userDetailsUri

    @Override
    protected void internalInit(boolean forceReinit) {
        CommonHelper.assertNotBlank("apiKeyUri", apiKeyUri);
        CommonHelper.assertNotBlank("userDetailsUri", userDetailsUri);
    }

    @Override
    void validate(Credentials credentials, WebContext context, SessionStore sessionStore) {

        init()

        TokenCredentials alaApiKeyCredentials = (TokenCredentials) credentials

        AlaApiUserProfile alaApiUserProfile = fetchUserProfile(alaApiKeyCredentials.token)

        if (alaApiUserProfile.activated && !alaApiUserProfile.locked) {

            alaApiKeyCredentials.userProfile = alaApiUserProfile
        }
    }

    AlaApiUserProfile fetchUserProfile(String apiKey) {

        AlaApiUserProfile alaApiUserProfile = new AlaApiUserProfile()

        HTTPRequest apiKeyRequest = new HTTPRequest(HTTPRequest.Method.GET, URI.create("${apiKeyUri}/${apiKey}"))
        HTTPResponse apiKeyResponse = apiKeyRequest.send()

        apiKeyResponse.ensureStatusCode(HTTPResponse.SC_OK)
        apiKeyResponse.ensureEntityContentType()

        ContentType ct = apiKeyResponse.getEntityContentType()

        if (ct.matches(ContentType.APPLICATION_JSON)) {

            JSONObject apiKeyCheck = apiKeyResponse.contentAsJSONObject

            if (!apiKeyCheck.getOrDefault("valid", false)) {
                throw new CredentialsException("invalid apiKey: '${apiKey}'")
            }

            String userId = (String) apiKeyCheck.get("userId")
            String email = (String) apiKeyCheck.get("email")

            alaApiUserProfile.userId = userId
            alaApiUserProfile.email = email

        } else {

            throw new ParseException("Unexpected ApiKey Content-Type, must be ${ContentType.APPLICATION_JSON}")
        }


        HTTPRequest userDetailsRequest = new HTTPRequest(HTTPRequest.Method.POST, URI.create(userDetailsUri))
        userDetailsRequest.setQuery("userName=${alaApiUserProfile.userId}")

        HTTPResponse userDetailsResponse = userDetailsRequest.send()

        userDetailsResponse.ensureStatusCode(HTTPResponse.SC_OK)
        userDetailsResponse.ensureEntityContentType()

        ct = userDetailsResponse.getEntityContentType()

        if (ct.matches(ContentType.APPLICATION_JSON)) {

            JSONObject userDetails = userDetailsResponse.contentAsJSONObject

            boolean activated = (Boolean) userDetails.getOrDefault("activated", false)
            boolean locked = (Boolean) userDetails.getOrDefault("locked", true)
            String firstName = (String) userDetails.getOrDefault("firstName", "")
            String lastName = (String) userDetails.getOrDefault("lastName", "")

            List<String> userRoles = userDetails.getOrDefault("roles", Collections.emptyList())

            alaApiUserProfile.firstName = firstName
            alaApiUserProfile.lastName = lastName

            alaApiUserProfile.activated = activated
            alaApiUserProfile.locked = locked

            alaApiUserProfile.attributes = userDetails
            alaApiUserProfile.addRoles(userRoles)

        } else {

            throw new ParseException("Unexpected UserDetails Content-Type, must be ${ContentType.APPLICATION_JSON}")
        }

        return alaApiUserProfile
    }
}