package au.org.ala.ws.security

import retrofit2.Call
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

interface ApiKeyClient {

    @GET('/ws/check')
    Call<CheckApiKeyResult> checkApiKey(@Query('apikey') String apiKey)

}