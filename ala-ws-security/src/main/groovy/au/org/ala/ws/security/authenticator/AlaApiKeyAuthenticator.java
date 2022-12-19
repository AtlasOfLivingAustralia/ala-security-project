package au.org.ala.ws.security.authenticator

import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.web.UserDetails
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
    UserDetailsClient userDetailsClient

    @Override
    protected void internalInit(boolean forceReinit) {
        CommonHelper.assertNotNull("apiKeyClient", apiKeyClient)
        CommonHelper.assertNotNull("userDetailsClient", userDetailsClient)
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

        def checkApiKeyCall = apiKeyClient.checkApiKey(apiKey)

        def checkApiKeyResponse = checkApiKeyCall.execute()

        if (!checkApiKeyResponse.successful) {
            throw new CredentialsException("apikey check failed : ${checkApiKeyResponse.message()}")
        }

        def apiKeyCheck = checkApiKeyResponse.body()

        if (apiKeyCheck.valid) {

            String userId = apiKeyCheck.userId

            alaApiUserProfile.userId = userId
            alaApiUserProfile.email = apiKeyCheck.email

            Call<UserDetails> userDetailsCall = userDetailsClient.getUserDetails(userId, true)

            Response<UserDetails> response = userDetailsCall.execute()

            if (response.successful) {

                UserDetails userDetails = response.body()

                alaApiUserProfile.givenName = userDetails.firstName
                alaApiUserProfile.familyName = userDetails.lastName
                alaApiUserProfile.activated = userDetails.activated
                alaApiUserProfile.locked = userDetails.locked ?: true
                alaApiUserProfile.addRoles(userDetails.roles)

                alaApiUserProfile.attributes = userDetails.props
             }

            return alaApiUserProfile
        }

        throw new CredentialsException("invalid apiKey: '${apiKey}'")
    }
}