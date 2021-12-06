package au.ala.org.ws.security

import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority

/**
 * Converts a single Authority containing an attribute "authority" with a comma separated list of roles into
 * a Set of Authorities, one for each role.
 */
@CompileStatic
@Slf4j
class AlaRoleMapper implements GrantedAuthoritiesMapper {
    @Override
    Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {

        Set roles = new HashSet()
        authorities.each {
            if (it instanceof OAuth2UserAuthority) {
                mapOAuth2UserAuthority((OAuth2UserAuthority)it, roles)
            }
            else {
                log.warn("Mapper encountered an authority not of type OAuth2UserAuthority!")
                roles.add(it)
            }
        }
        roles
    }

    private void mapOAuth2UserAuthority(OAuth2UserAuthority authority, Set roles) {
        def authorityAttribute = authority.attributes['authority']
        if (log.isDebugEnabled()) {
            log.debug("Mapping authority: ${authority.toString()} with authority ${authority.getAuthority()} with attribute: ${authorityAttribute}")
        }
        if (authorityAttribute && authorityAttribute instanceof String) {
            ((String)authorityAttribute).split(',').each{String role -> roles.add(new SimpleGrantedAuthority(role))}
        }
        else {
            log.warn("The OAuth2UserAuthority didn't have an authority attribute we could map.")
            roles.add(authority)
        }
    }
}
