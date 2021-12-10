package au.org.ala.ws.security

class AnnotatedClassController {
    def action1() {}
    def action2() {}

    @SkipAuthCheck
    def action3() {}
}
