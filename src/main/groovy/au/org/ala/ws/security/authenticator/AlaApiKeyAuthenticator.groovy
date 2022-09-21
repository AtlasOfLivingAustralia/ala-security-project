package au.org.ala.ws.security.authenticator

import au.org.ala.ws.security.ApiKeyClient
import au.org.ala.ws.security.profile.AlaApiUserProfile
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.credentials.authenticator.Authenticator
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.util.CommonHelper
import org.pac4j.core.util.InitializableObject
import retrofit2.Call
import retrofit2.Response

class AlaApiKeyAuthenticator extends InitializableObject implements Authenticator {

    ApiKeyClient apiKeyClient

    @Override
    protected void internalInit(boolean forceReinit) {
        CommonHelper.assertNotNull("apiKeyClient", apiKeyClient)
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

        Call<Map<String, Object>> checkApiKeyCall = apiKeyClient.checkApiKey(apiKey)

        Response<Map<String, Object>> checkApiKeyResponse = checkApiKeyCall.execute()

        if (!checkApiKeyResponse.successful) {
            throw new CredentialsException("apikey check failed : ${checkApiKeyResponse.message()}")
        }

        Map<String, Object> apiKeyCheck = checkApiKeyResponse.body()

        if (apiKeyCheck.valid) {

            String userId = apiKeyCheck.userId

            alaApiUserProfile.userId = userId
            alaApiUserProfile.email = apiKeyCheck.email

            Call<Map<String, Object>> userDetailsCall = apiKeyClient.getUserDetails(userId, true)

            Response<Map<String, Object>> response = userDetailsCall.execute()

            if (response.successful) {

                Map<String, Object> userDetails = response.body()

                alaApiUserProfile.firstName = userDetails.firstName
                alaApiUserProfile.lastName = userDetails.lastName
                alaApiUserProfile.activated = userDetails.activated
                alaApiUserProfile.locked = userDetails.getOrDefault('locked', true)
                alaApiUserProfile.addRoles(userDetails.getOrDefault('roles', []))

                alaApiUserProfile.attributes = userDetails
             }

            return alaApiUserProfile
        }

        throw new CredentialsException("invalid apiKey: '${apiKey}'")
    }
}