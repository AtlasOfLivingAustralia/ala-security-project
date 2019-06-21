import au.org.ala.cas.client.AjaxAwareGatewayStorage
import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl

userDetails {
    url = 'https://auth.ala.org.au/userdetails/'
    readTimeout = 0 // disable read timeouts for user details because some services are slooooow...
}
security {
    cas {
        appServerName = null
        casServerName = 'https://auth.ala.org.au'
        casServerUrlPrefix = 'https://auth.ala.org.au/cas'
        loginUrl = 'https://auth.ala.org.au/cas/login'
        logoutUrl = 'https://auth.ala.org.au/cas/logout'
        bypass = false
        gateway = false
        renew = false
        encodeServiceUrl = true
        uriFilterPattern = ['/admin/*','/testAuth','/authTest/*']
        uriExclusionFilterPattern = ['/assets/.*','/static/.*','/fonts/.*','/images/.*','/css/.*','/js/.*','/less/.*']
        authenticateOnlyIfLoggedInPattern = []
        authenticateOnlyIfLoggedInFilterPattern = ['/']
        gatewayFilterPattern = []
        gatewayIfCookieFilterPattern = []
        gatewayStorageClass = DefaultGatewayResolverImpl.name
        roleAttribute = 'role'
        ignoreCase = true
//        encodeServiceUrl = 'true'
//        contextPath = '/set-this-to-override-default'
    }
}

grails {
    cache {
        config {
            defaults {
                eternal = false
                overflowToDisk = false
                maxElementsInMemory = 20000
                timeToLiveSeconds = 3600
            }
            cache{
                name = 'userListCache'
            }
            cache {
                name = 'userMapCache'
            }
        }
    }
}
