package au.org.ala.ws.security;

import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Query;

public interface ApiKeyClient {
    @GET("/ws/check")
    public abstract Call<CheckApiKeyResult> checkApiKey(@Query("apikey") String apiKey);
}
