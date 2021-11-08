package au.ala.org.ws.security

import java.security.Principal

class AuthenticatedUser implements Principal {

    String email
    String userId
    List roles

    @Override
    String getName() {
        return email
    }
}
