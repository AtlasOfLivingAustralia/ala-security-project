package au.org.ala.ws.security

import retrofit2.Call
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

interface ApiKeyClient {

    @GET('/apikey/ws/check')
    Call<Map<String, Object>> checkApiKey(@Query('apikey') String apiKey)

    @POST('/userDetails/getUserDetails')
    Call<Map<String, Object>> getUserDetails(@Query("userName") String username, @Query("includeProps") boolean includeProps)
}