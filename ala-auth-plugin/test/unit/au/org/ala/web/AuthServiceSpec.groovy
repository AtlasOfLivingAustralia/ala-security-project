package au.org.ala.web

import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.userdetails.UserDetailsFromIdListResponse
import grails.test.mixin.*
import retrofit2.mock.Calls
import spock.lang.Specification

@TestFor(AuthService)
class AuthServiceSpec extends Specification {

    def setup() {
        grailsApplication.config.userDetails.url = 'http://auth.ala.org.au/userdetails/'
    }

    def testGetUserDetailsById() {
        setup:
        def mockUserDetailsClient = Stub(UserDetailsClient)
        def response = new UserDetailsFromIdListResponse()
        response.users = [
                '546': new UserDetails(userId: "546", userName: "user1@gmail.com", firstName: "Jimmy-Bob", lastName: "Dursten"),
                '4568': new UserDetails(userId: "4568", userName: "user2@hotmail.com", firstName: "James Robert", lastName: "Durden"),
                '8744': new UserDetails(userId: "8744", userName: "user3@fake.edu.au", firstName: "Jim Rob", lastName: "Durpen")
        ]
        response.invalidIds = [ 575 ]
        response.success = true
        mockUserDetailsClient.getUserDetailsFromIdList(_) >> Calls.response(response)

        service.userDetailsClient = mockUserDetailsClient

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
