package au.org.ala.ws.security;

import au.org.ala.ws.security.client.AlaAuthClient;
import au.org.ala.ws.security.profile.AlaUserProfile;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.FindBest;
import org.pac4j.jee.context.JEEContextFactory;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.*;

/**
 * Spring based Webservice Authentication Filter. This filter supports 3 modes of authentication:
 * 1) JSON Web tokens
 * 2) Legacy API keys using ALA's apikey app
 * 3) Whitelist IP
 */
public class AlaWebServiceAuthFilter extends OncePerRequestFilter {
    public static final Logger log = LoggerFactory.getLogger(AlaWebServiceAuthFilter.class);

    private Config config;
    private AlaAuthClient alaAuthClient;

    public AlaWebServiceAuthFilter(Config config, AlaAuthClient alaAuthClient) {
        this.config = config;
        this.alaAuthClient = alaAuthClient;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        try {

            WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response);

            Optional<Credentials> optCredentials = alaAuthClient.getCredentials(context, config.getSessionStore());
            if (optCredentials.isPresent()) {

                Credentials credentials = optCredentials.get();

                Optional<UserProfile> optProfile = alaAuthClient.getUserProfile(credentials, context, config.getSessionStore());
                if (optProfile.isPresent()) {

                    UserProfile userProfile = optProfile.get();

                    setAuthenticatedUserAsPrincipal(userProfile);

                    ProfileManager profileManager = new ProfileManager(context, config.getSessionStore());
                    profileManager.setConfig(config);

                    profileManager.save(alaAuthClient.getSaveProfileInSession(context, userProfile), userProfile, alaAuthClient.isMultiProfile(context, userProfile));
                } else if (credentials instanceof OidcCredentials) {
                    // This is a machine-to-machine request, create a UserProfile with userId:null and roles:scope
                    final Set<String> scope = new HashSet<>(((OidcCredentials) credentials).getAccessToken().getScope().toStringList());
                    UserProfile userProfile = new AlaUserProfile() {
                        @Override
                        public String getName() {
                            return null;
                        }

                        @Override
                        public String getUserId() {
                            return null;
                        }

                        @Override
                        public String getEmail() {
                            return null;
                        }

                        @Override
                        public String getGivenName() {
                            return null;
                        }

                        @Override
                        public String getFamilyName() {
                            return null;
                        }

                        @Override
                        public String getId() {
                            return null;
                        }

                        @Override
                        public void setId(String s) {

                        }

                        @Override
                        public String getTypedId() {
                            return null;
                        }

                        @Override
                        public String getUsername() {
                            return null;
                        }

                        @Override
                        public Object getAttribute(String s) {
                            return null;
                        }

                        @Override
                        public Map<String, Object> getAttributes() {
                            return null;
                        }

                        @Override
                        public boolean containsAttribute(String s) {
                            return false;
                        }

                        @Override
                        public void addAttribute(String s, Object o) {

                        }

                        @Override
                        public void removeAttribute(String s) {

                        }

                        @Override
                        public void addAuthenticationAttribute(String s, Object o) {

                        }

                        @Override
                        public void removeAuthenticationAttribute(String s) {

                        }

                        @Override
                        public void addRole(String s) {

                        }

                        @Override
                        public void addRoles(Collection<String> collection) {

                        }

                        @Override
                        public Set<String> getRoles() {
                            return scope;
                        }

                        @Override
                        public void addPermission(String s) {

                        }

                        @Override
                        public void addPermissions(Collection<String> collection) {

                        }

                        @Override
                        public Set<String> getPermissions() {
                            return null;
                        }

                        @Override
                        public boolean isRemembered() {
                            return false;
                        }

                        @Override
                        public void setRemembered(boolean b) {

                        }

                        @Override
                        public String getClientName() {
                            return null;
                        }

                        @Override
                        public void setClientName(String s) {

                        }

                        @Override
                        public String getLinkedId() {
                            return null;
                        }

                        @Override
                        public void setLinkedId(String s) {

                        }

                        @Override
                        public boolean isExpired() {
                            return false;
                        }

                        @Override
                        public Principal asPrincipal() {
                            return null;
                        }
                    };

                    setAuthenticatedUserAsPrincipal(userProfile);
                    ProfileManager profileManager = new ProfileManager(context, config.getSessionStore());
                    profileManager.setConfig(config);
                    profileManager.save(alaAuthClient.getSaveProfileInSession(context, userProfile), userProfile, alaAuthClient.isMultiProfile(context, userProfile));
                }
            }
        } catch (CredentialsException e) {

            log.info("authentication failed invalid credentials", e);

            response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
            return;

        }


        chain.doFilter(request, response);
    }

    private void setAuthenticatedUserAsPrincipal(UserProfile userProfile) {

        SecurityContext securityContext = SecurityContextHolder.getContext();
        List<String> credentials = new ArrayList<String>();
        final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

        userProfile.getRoles().forEach(s -> authorities.add(new SimpleGrantedAuthority(s)));

        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(userProfile, credentials, authorities);
        token.setAuthenticated(true);
        securityContext.setAuthentication(token);
    }

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }

    public AlaAuthClient getAlaAuthClient() {
        return alaAuthClient;
    }

    public void setAlaAuthClient(AlaAuthClient alaAuthClient) {
        this.alaAuthClient = alaAuthClient;
    }
}
