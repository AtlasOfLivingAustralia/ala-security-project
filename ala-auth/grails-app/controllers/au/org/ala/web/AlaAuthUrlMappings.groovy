package au.org.ala.web

class AlaAuthUrlMappings {

    static mappings = {
        name login: "/login" (controller: 'login', action: 'index', plugin: 'alaAuth')
    }
}