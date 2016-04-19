package au.org.ala.ws.filter

import au.org.ala.ws.validation.ValidatedParameter
import grails.test.mixin.TestFor
import grails.test.mixin.TestMixin
import grails.test.mixin.support.GrailsUnitTestMixin
import grails.test.mixin.web.FiltersUnitTestMixin
import spock.lang.Specification

import javax.validation.constraints.Min
import javax.validation.constraints.NotNull

@TestFor(WSFilters)
@TestMixin([GrailsUnitTestMixin, FiltersUnitTestMixin])
class WSFiltersSpec extends Specification {
    def controller = new TestController()

    void "invalid parameters should result in a HTTP 400 (BAD_REQUEST)"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", TestController)

        when:

        withFilters(controller: "test", action: "action1") {
            controller.action1()
        }

        then:
        response.status == 400
    }

    void "valid parameters should result in a HTTP 200 (OK)"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", TestController)

        when:
        params.param1 = "test"
        params.param2 = 666
        withFilters(controller: "test", action: "action1") {
            controller.action1()
        }

        then:
        response.status == 200
    }
}

/**
 * This class mimics the runtime Grails controller classes, after they have had the BeanValidationAST and the grails web
 * ASTs applied:
 *
 * - BeanValidationAST adds @ValidatedParameter to every parameter that is annotated with a JSR303 constraint; and
 * 0 Grails creates a no-arg version of each controller action
 */
class TestController {
    def action1(
            @ValidatedParameter(paramName = "param1", paramType = String) @NotNull String param1,
            @ValidatedParameter(paramName = "param2", paramType = Integer) @Min(2L) int param2) {

    }

    def action1() {}
}