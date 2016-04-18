package au.org.ala.ws.controller

import grails.converters.JSON

import static org.apache.http.HttpStatus.SC_BAD_REQUEST
import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR
import static org.apache.http.HttpStatus.SC_NOT_FOUND
import static org.apache.http.HttpStatus.SC_OK
import static org.apache.http.HttpStatus.SC_UNAUTHORIZED

abstract class BasicWSController {
    static final String CONTEXT_TYPE_JSON = "application/json"

    protected notFound = { String message = null ->
        sendError(SC_NOT_FOUND, message ?: "")
    }

    protected badRequest = { String message = null ->
        sendError(SC_BAD_REQUEST, message ?: "")
    }

    protected notAuthorised = { String message = null ->
        sendError(SC_UNAUTHORIZED, message ?: "You do not have permission to perform the requested action.")
    }

    /**
     * Renders the provided Map as a JSON response with status code 200
     *
     * @param resp The map to render as JSON data on the response
     */
    protected success = { resp ->
        response.status = SC_OK
        response.setContentType(CONTEXT_TYPE_JSON)
        render resp as JSON
    }

    protected saveFailed = {
        sendError(SC_INTERNAL_SERVER_ERROR)
    }

    protected sendError = { int status, String msg = null ->
        response.status = status
        response.sendError(status, msg)
    }

    /**
     * Renders the WS response structure (see ala.org.au.ws.service.WebService) as JSON, or sends a HTTP error if resp.status != 200.
     *
     * @param resp response structure as returned by the ala.org.au.ws.service.WebService class
     */
    protected handleWSResponse(Map resp) {
        if (resp) {
            if (resp.statusCode != SC_OK) {
                log.debug "Response status ${resp.statusCode} returned from operation"
                response.status = resp.statusCode
                sendError(resp.statusCode, resp.error ?: "")
            } else {
                response.setContentType(CONTEXT_TYPE_JSON)
                render resp.resp as JSON
            }
        } else {
            response.setContentType(CONTEXT_TYPE_JSON)
            render [:] as JSON
        }
    }
}