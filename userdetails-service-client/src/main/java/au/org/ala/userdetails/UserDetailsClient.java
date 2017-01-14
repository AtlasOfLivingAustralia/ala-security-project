package au.org.ala.userdetails;

import au.org.ala.web.UserDetails;
import com.squareup.moshi.Moshi;
import com.squareup.moshi.Rfc3339DateJsonAdapter;
import lombok.*;
import lombok.experimental.Accessors;
import lombok.extern.java.Log;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.moshi.MoshiConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.POST;
import retrofit2.http.Query;

import java.util.Date;
import java.util.List;
import java.util.Map;

public interface UserDetailsClient {

    String GET_USER_DETAILS_PATH = "userDetails/getUserDetails";
    String GET_USER_DETAILS_FROM_ID_LIST_PATH = "userDetails/getUserDetailsFromIdList";
    String GET_USER_LIST_FULL_PATH = "userDetails/getUserListFull";
    String GET_USER_LIST_PATH = "userDetails/getUserList";
    String GET_USER_LIST_WITH_IDS_PATH = "userDetails/getUserListWithIds";

    /**
     * Return a JSON object containing id, email and display name for a given user, use includeProps=true to get additional information such as organisation
     * @param username Can be either a numeric id or an email address id
     * @param includeProps True to include extended properties such as organisation, telephone, etc.
     * @return A call that will return a UserDetails object.
     */
    @POST(GET_USER_DETAILS_PATH)
    Call<UserDetails> getUserDetails(@Query("userName") String username, @Query("includeProps") boolean includeProps);

    /**
     * return the UserDetails objects for a list of user ids.
     * @param request The request body - accepts numeric ids only.
     * @return A response object with the matched UserDetails and any missing ids and or error messages.
     */
    @POST(GET_USER_DETAILS_FROM_ID_LIST_PATH)
    Call<AllUserDetailsResponse> getUserDetailsFromIdList(@Body AllUserDetailsRequest request);

    /**
     * Return all the UserDetails.  This will be super slow probably so caching the result is advised.
     * @return A call that returns all the UserDetails.
     */
    @Deprecated
    @POST(GET_USER_LIST_FULL_PATH)
    Call<List<UserDetails>> getUserListFull();

    /**
     * Return a map of User email to User display name.  Returns all known users.
     * @return A map of User email to User display name
     */
    @Deprecated
    @POST(GET_USER_LIST_PATH)
    Call<Map<String, String>> getUserList();

    /**
     * Return a map of User numeric id to User display name.  Returns all known users.
     * @return A map of User numeric id to User display name
     */
    @Deprecated
    @POST(GET_USER_LIST_WITH_IDS_PATH)
    Call<Map<String, String>> getUserListWithIds();

    /**
     * A Builder for generating UserDetailsClient instances.
     */
    @Log
    @Getter
    @Setter
    @Accessors(fluent = true, chain = true)
    @RequiredArgsConstructor
    class Builder {
        private final OkHttpClient okHttpClient;
        private final HttpUrl baseUrl;

        private Moshi moshi = null;

        /**
         * Create a Builder using an okHttpClient and String baseUrl.  The baseUrl will be
         * converted to an HttpUrl and a trailing / will be added if required.
         * @param okHttpClient The OkHttpClient to use
         * @param baseUrl The base URL of the User Details service
         */
        public Builder(OkHttpClient okHttpClient, String baseUrl) {
            this.okHttpClient = okHttpClient;
            if (!baseUrl.endsWith("/")) {
                log.warning("User Details Client Base URL (" + baseUrl + ") does not end with a /");
                baseUrl += "/";
            }
            this.baseUrl = HttpUrl.parse(baseUrl);
        }

        /**
         * Create the UserDetailsClient instance.  If a moshi instance is not supplied, one will
         * be created.
         *
         * @return A UserDetailsClient using the supplied okhttpclient, baseUrl and moshi.
         */
        public UserDetailsClient build() {
            val builder = new Retrofit.Builder();

            Moshi moshi = this.moshi;
            if (moshi == null) {
                moshi = new Moshi.Builder()
                        .add(Date.class, new Rfc3339DateJsonAdapter())
                        .build();
            }

            builder.addConverterFactory(MoshiConverterFactory.create(moshi))
                    .client(okHttpClient)
                    .baseUrl(baseUrl);

            return builder.build().create(UserDetailsClient.class);
        }
    }

}
