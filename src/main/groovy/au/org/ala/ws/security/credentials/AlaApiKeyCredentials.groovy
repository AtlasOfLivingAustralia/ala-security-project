package au.org.ala.ws.security.credentials

import org.pac4j.core.credentials.Credentials
import org.pac4j.core.util.CommonHelper

class AlaApiKeyCredentials extends Credentials {

    private final String apiKey

    AlaApiKeyCredentials(String apiKey) {
        this.apiKey = apiKey
    }

    String getApiKey() {
        return apiKey
    }

    @Override
    boolean equals(Object o) {
        if (this == o) return true
        if (o == null || getClass() != o.getClass()) return false

        final AlaApiKeyCredentials that = (AlaApiKeyCredentials) o

        return (apiKey == that.apiKey)
    }

    @Override
    int hashCode() {
        return apiKey?.hashCode() ?: 0
    }

    @Override
    String toString() {
        return CommonHelper.toNiceString(this.getClass(), "apiKey", this.apiKey);
    }
}
