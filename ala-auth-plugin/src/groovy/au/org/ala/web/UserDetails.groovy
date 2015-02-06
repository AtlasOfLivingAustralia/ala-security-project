package au.org.ala.web

import java.io.Serializable

/**
 * Created with IntelliJ IDEA.
 *
 * @author "Nick dos Remedios <Nick.dosRemedios@csiro.au>"
 */
class UserDetails implements Serializable {

    private static final long serialVersionUID = 42L;

    String displayName // full name
    String userName    // email
    String userId      // numeric id
}
