package au.org.ala.web

import java.io.Serializable

/**
 * Created with IntelliJ IDEA.
 *
 * @author "Nick dos Remedios <Nick.dosRemedios@csiro.au>"
 */
class UserDetails implements Serializable {

    private static final long serialVersionUID = 43L;

    String displayName // full name
    String userName    // email
    String userId      // numeric id

    String primaryUserType // optional prop
    String secondaryUserType // optional prop
    String organisation // optional prop
    String city // optional prop
    String state // optional prop
    String telephone // optional prop
}
