package au.org.ala.web

import grails.converters.JSON
import grails.test.mixin.*
import spock.lang.Specification

@TestFor(AuthService)
class AuthServiceSpec extends Specification {

    def setup() {
        grailsApplication.config.userDetails.url = 'http://auth.ala.org.au/userdetails/'
        grailsApplication.config.userDetailsById.bulkPath = 'getUserDetailsFromIdList'
    }

    def testGetUserDetailsById() {
        setup:
        def mockHttpWebService = mockFor(HttpWebService)
        mockHttpWebService.demand.doPost(1) { url, path, port, postBody, contentType ->
            assert url == 'http://auth.ala.org.au/userdetails/getUserDetailsFromIdList'
            return [resp: JSON.parse('''{
  "users":{
     "546":{"userId": "546", "userName": "user1@gmail.com", "firstName": "Jimmy-Bob", "lastName": "Dursten"},
     "4568":{"userId": "4568", "userName": "user2@hotmail.com", "firstName": "James Robert", "lastName": "Durden"},
     "8744":{"userId": "8744", "userName": "user3@fake.edu.au", "firstName": "Jim Rob", "lastName": "Durpen"}
  },
  "invalidIds":[ 575 ],
  "success": true
}'''), error: null]
        }
        service.httpWebService = mockHttpWebService.createMock()

        when:
        def x = service.getUserDetailsById(['546','8744','4568','575'])

        then:
        x.success == true
        def users = x.users
        users['546'] instanceof UserDetails
        users['546'].userName == 'user1@gmail.com'
        x.invalidIds == [ 575 ]
    }
}
