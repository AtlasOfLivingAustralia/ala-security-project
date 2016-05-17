package au.org.ala.ws.security.service

class WsService {

    def get(String url) {
        return new URL(url).openConnection()
    }
}
