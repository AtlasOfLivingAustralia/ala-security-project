package au.org.ala.ws.security

import org.pac4j.core.credentials.Credentials
import org.pac4j.core.profile.UserProfile
import org.pac4j.http.client.direct.DirectBearerAuthClient
import spock.lang.Specification

class AlaWebServiceAuthUtilsSpec extends Specification {

    def 'claims from access_token'() {

        setup:
        AlaWebServiceAuthUtils alaWebServiceAuthUtils = new AlaWebServiceAuthUtils()

        alaWebServiceAuthUtils.jwtProperties = new JwtProperties()
        alaWebServiceAuthUtils.jwtProperties.userProfileFromAccessToken = true

        DirectBearerAuthClient bearerAuthClient = Mock(DirectBearerAuthClient)
        alaWebServiceAuthUtils.bearerClient = bearerAuthClient

        when:
        Optional<UserProfile> userProfile = alaWebServiceAuthUtils.jwtApiKeyInterceptor(null, null)

        then:
        1 * bearerAuthClient.getCredentials(_, _)
//        1 * bearerAuthClient.getCredentials(_, _) >> Optional.of(new Credentials() {
//            UserProfile getUserProfile() {
//                return null
//            }
//        })

        userProfile.isPresent()
        userProfile.get().attributes
    }
}
