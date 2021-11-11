package au.ala.org.ws.security;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.stream.Collectors;

/**
 * A customised OidcUserService service that ensures that all ALA roles
 * are available so that request.isUserInRole calls work properly.
 */
@Component
public class AlaOAuth2UserService extends OidcUserService {

    private final Set<String> userInfoScopes = new HashSet<>(
            Arrays.asList(OidcScopes.PROFILE, OidcScopes.EMAIL, OidcScopes.ADDRESS, OidcScopes.PHONE));

    private static final String MISSING_USER_INFO_URI_ERROR_CODE = "missing_user_info_uri";

    private static final String MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute";

    private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

    private Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter = new OAuth2UserRequestEntityConverter();

    private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE =
            new ParameterizedTypeReference<Map<String, Object>>() {};

    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = new DefaultOAuth2UserService();

    private RestOperations restOperations;

    public AlaOAuth2UserService() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        this.restOperations = restTemplate;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");
        OidcUserInfo userInfo = null;
        if (this.shouldRetrieveUserInfo(userRequest)) {
            OAuth2User oauth2User = this.oauth2UserService.loadUser(userRequest);
            userInfo = new OidcUserInfo(oauth2User.getAttributes());

            // https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

            // 1) The sub (subject) Claim MUST always be returned in the UserInfo Response
            if (userInfo.getSubject() == null) {
                OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            }

            // 2) Due to the possibility of token substitution attacks (see Section 16.11),
            // the UserInfo Response is not guaranteed to be about the End-User
            // identified by the sub (subject) element of the ID Token.
            // The sub Claim in the UserInfo Response MUST be verified to exactly match
            // the sub Claim in the ID Token; if they do not match,
            // the UserInfo Response values MUST NOT be used.
            if (!userInfo.getSubject().equals(userRequest.getIdToken().getSubject())) {
                OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            }
        }

//        Set<GrantedAuthority> authorities = Collections.singleton(
//                new OidcUserAuthority(userRequest.getIdToken(), userInfo));

        Collection<String> authoritiesUserInfo =  (Collection<String>) userInfo.getClaims().get("role");

        Set<GrantedAuthority> authorities = authoritiesUserInfo
                .stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toSet());

        OidcUser user;

        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        if (StringUtils.hasText(userNameAttributeName)) {
            user = new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo, userNameAttributeName);
        } else {
            user = new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo);
        }

        return user;
    }

    private boolean shouldRetrieveUserInfo(OidcUserRequest userRequest) {
        // Auto-disabled if UserInfo Endpoint URI is not provided
        if (StringUtils.isEmpty(userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUri())) {

            return false;
        }

        // The Claims requested by the profile, email, address, and phone scope values
        // are returned from the UserInfo Endpoint (as described in Section 5.3.2),
        // when a response_type value is used that results in an Access Token being issued.
        // However, when no Access Token is issued, which is the case for the response_type=id_token,
        // the resulting Claims are returned in the ID Token.
        // The Authorization Code Grant Flow, which is response_type=code, results in an Access Token being issued.
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(
                userRequest.getClientRegistration().getAuthorizationGrantType())) {

            // Return true if there is at least one match between the authorized scope(s) and UserInfo scope(s)
            return CollectionUtils.containsAny(userRequest.getAccessToken().getScopes(), this.userInfoScopes);
        }

        return false;
    }
}