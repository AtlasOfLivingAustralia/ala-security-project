package au.org.ala.ws.tokens

import okhttp3.Interceptor
import okhttp3.Response

/**
 * okhttp interceptor that inserts a bearer token into the request
 */
class TokenInterceptor implements Interceptor {

    private final TokenService tokenService

    TokenInterceptor(TokenService tokenService) {
        this.tokenService = tokenService
    }

    @Override
    Response intercept(Chain chain) throws IOException {
        return chain.proceed(
                chain.request().newBuilder()
                        .addHeader('Authorization', tokenService.getAuthToken(false).toAuthorizationHeader())
                        .build()
        )
    }

}
