package au.org.ala.ws.security.service

class WebService {

    def get(String url) {
        return new URL(url).openConnection()
    }
}
