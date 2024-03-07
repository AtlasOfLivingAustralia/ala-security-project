package au.org.ala.web;

import au.org.ala.pac4j.core.logout.CognitoLogoutActionBuilder;
import org.pac4j.core.logout.LogoutActionBuilder;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.logout.OidcLogoutActionBuilder;

public enum LogoutActionType {

    DEFAULT {
        public LogoutActionBuilder getLogoutActionBuilder(OidcConfiguration oidcConfiguration) {
            // TODO this should always return the same as the default PAC4j oidcClient.logoutActionBuilder.
            return new OidcLogoutActionBuilder(oidcConfiguration);
        }
    },
    COGNITO {
        @Override
        public LogoutActionBuilder getLogoutActionBuilder(OidcConfiguration oidcConfiguration) {
            return new CognitoLogoutActionBuilder(oidcConfiguration);
        }
    };

    abstract public LogoutActionBuilder getLogoutActionBuilder(OidcConfiguration oidcConfiguration);
}
