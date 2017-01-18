userDetails.url = 'https://auth.ala.org.au/userdetails/'
security {
    cas {
        appServerName = null
        casServerName = 'https://auth.ala.org.au'
        casServerUrlPrefix = 'https://auth.ala.org.au/cas'
        loginUrl = 'https://auth.ala.org.au/cas/login'
        logoutUrl = 'https://auth.ala.org.au/cas/logout'
        bypass = false
        uriFilterPattern = '/admin/.*,/testAuth,/authTest/.*'
        uriExclusionFilterPattern = '/assets/.*,/images/.*,/css/.*,/js/.*,/less/.*'
        authenticateOnlyIfLoggedInPattern =  ''
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
