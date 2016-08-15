package au.org.ala.web


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

    Set<String> roles = new HashSet()

    /**
     * Returns true if the user represented by this UserDetails has the supplied role.
     * @param role the role to check.
     * @return true if this user has the supplied role.
     */
    boolean hasRole(String role) {
        return roles.contains(role)
    }
}
