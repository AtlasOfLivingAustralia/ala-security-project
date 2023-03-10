package au.org.ala.web;

import au.org.ala.pac4j.core.logout.CognitoLogoutActionBuilder;
import org.pac4j.core.logout.LogoutActionBuilder;
import org.pac4j.oidc.config.OidcConfiguration;

public enum LogoutActionType {

    DEFAULT {
        public LogoutActionBuilder getLogoutActionBuilder(OidcConfiguration oidcConfiguration) {
            return null;
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
