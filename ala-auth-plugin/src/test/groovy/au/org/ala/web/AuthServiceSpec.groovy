package au.org.ala.web

import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.userdetails.UserDetailsFromIdListResponse
import grails.testing.services.ServiceUnitTest
import grails.web.mapping.LinkGenerator
import org.grails.spring.beans.factory.InstanceFactoryBean
import retrofit2.mock.Calls
import spock.lang.Specification

class AuthServiceSpec extends Specification implements ServiceUnitTest<AuthService> {


    def setup() {

        grailsApplication.config.userDetails.url = 'http://auth.ala.org.au/userdetails/'

        defineBeans {
            linkGenerator(InstanceFactoryBean, Stub(LinkGenerator), LinkGenerator)
        }
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

    def testGetUserDetailsById_null() {
        setup:
        def mockUserDetailsClient = Stub(UserDetailsClient)
        service.userDetailsClient = mockUserDetailsClient

        when:
        mockUserDetailsClient.getUserDetailsFromIdList(_) >> Calls.response(null)
        def x = service.getUserDetailsById([])

        then:
        x == null
    }

    def testGetUserForUserId() {
        setup:
        def mockUserDetailsClient = Stub(UserDetailsClient)
        def response = new UserDetails(userId: "546", userName: "user1@gmail.com", firstName: "Jimmy-Bob", lastName: "Dursten")
        mockUserDetailsClient.getUserDetails('546', true) >> Calls.response(response)

        service.userDetailsClient = mockUserDetailsClient

        when:
        def x = service.getUserForUserId('546')

        then:
        x != null
        x.userName == "user1@gmail.com"
        x.userId == "546"
        x.firstName == "Jimmy-Bob"
        x.lastName == "Dursten"
    }

    def testGetUserForUserId_nullUserId() {
        setup:
        def mockUserDetailsClient = Stub(UserDetailsClient)

        service.userDetailsClient = mockUserDetailsClient

        when:
        def x = service.getUserForUserId(null)

        then:
        x == null
    }

    def testGetUserForUserId_nullUser() {
        setup:
        def mockUserDetailsClient = Stub(UserDetailsClient)
        mockUserDetailsClient.getUserDetails('546', true) >> Calls.response(null)

        service.userDetailsClient = mockUserDetailsClient

        when:
        def x = service.getUserForUserId('546')

        then:
        x == null
    }

    def testGetUserForEmailAddress() {
        setup:
        def mockUserDetailsClient = Stub(UserDetailsClient)
        def response = new UserDetails(userId: "546", userName: "user1@gmail.com", firstName: "Jimmy-Bob", lastName: "Dursten")
        mockUserDetailsClient.getUserDetails('user1@gmail.com', true) >> Calls.response(response)

        service.userDetailsClient = mockUserDetailsClient

        when:
        def x = service.getUserForEmailAddress('user1@gmail.com')

        then:
        x != null
        x.userName == "user1@gmail.com"
        x.userId == "546"
        x.firstName == "Jimmy-Bob"
        x.lastName == "Dursten"
    }

    def testGetUserForEmailAddress_nullUserEmail() {
        setup:
        def mockUserDetailsClient = Stub(UserDetailsClient)

        service.userDetailsClient = mockUserDetailsClient

        when:
        def x = service.getUserForEmailAddress(null)

        then:
        x == null
    }

    def testGetUserForEmailAddress_nullUser() {
        setup:
        def mockUserDetailsClient = Stub(UserDetailsClient)
        mockUserDetailsClient.getUserDetails('user1@gmail.com', true) >> Calls.response(null)

        service.userDetailsClient = mockUserDetailsClient

        when:
        def x = service.getUserForEmailAddress('user1@gmail.com')

        then:
        x == null
    }
}
