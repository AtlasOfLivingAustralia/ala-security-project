package au.org.ala.ws.security

import au.ala.org.ws.security.RequireAuth

@RequireAuth
class DummyController {

    def action1(){
        println("running")
    }

    def action2(){
        println("running")
    }
}