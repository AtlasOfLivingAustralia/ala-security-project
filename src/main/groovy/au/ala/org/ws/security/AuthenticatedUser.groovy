package au.ala.org.ws.security

import java.security.Principal

class AuthenticatedUser implements Principal {

    String email
    String userId
    List roles
    Map attributes

    @Override
    String getName() {
        return email
    }
}
