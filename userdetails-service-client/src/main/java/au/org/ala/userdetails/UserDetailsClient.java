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
import retrofit2.http.GET;
import retrofit2.http.POST;
import retrofit2.http.Query;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * An interface that represents the exposed web services of the UserDetails application.
 *
 * Use the UserDetailsClient.Builder or Retrofit to generate an instance.
 */
public interface UserDetailsClient {

    String GET_USER_DETAILS_PATH = "userDetails/getUserDetails";
    String GET_USER_DETAILS_FROM_ID_LIST_PATH = "userDetails/getUserDetailsFromIdList";
    String GET_USER_LIST_FULL_PATH = "userDetails/getUserListFull";
    String GET_USER_LIST_PATH = "userDetails/getUserList";
    String GET_USER_LIST_WITH_IDS_PATH = "userDetails/getUserListWithIds";
    String GET_USER_DETAILS_BY_ROLE_PATH = "userDetails/byRole";
    String SEARCH_USERDETAILS_PATH = "userDetails/search";
    String GET_USER_STATS_PATH = "ws/getUserStats";

    /**
     * Return a JSON object containing id, email and display name for a given user, use includeProps=true to get additional information such as organisation
     *
     * @param username     Can be either a numeric id or an email address id
     * @param includeProps True to include extended properties such as organisation, telephone, etc.
     * @return A call that will return a UserDetails object.
     */
    @POST(GET_USER_DETAILS_PATH)
    Call<UserDetails> getUserDetails(@Query("userName") String username, @Query("includeProps") boolean includeProps);

    /**
     * return the UserDetails objects for a list of user ids.
     *
     * @param request The request body - accepts numeric ids only.
     * @return A response object with the matched UserDetails and any missing ids and or error messages.
     */
    @POST(GET_USER_DETAILS_FROM_ID_LIST_PATH)
    Call<UserDetailsFromIdListResponse> getUserDetailsFromIdList(@Body UserDetailsFromIdListRequest request);

    /**
     * return the User stats
     * @return A response object with the user stats
     */
    @GET(GET_USER_STATS_PATH)
    Call<UserStatsResponse> getUserStats();

    /**
     * Get the user details for all users with a given role, with optional filtering by user id / username / email
     * @param role The role to filter for (eg ROLE_USER)
     * @param includeProps Whether to include extended properties or not
     * @param ids List of numeric ids as Strings / user names / passwords
     * @return The list of users that match the restrictions
     */
    @GET(GET_USER_DETAILS_BY_ROLE_PATH)
    Call<List<UserDetails>> getUserDetailsByRole(@Query("role") String role, @Query("includeProps") boolean includeProps, @Query("id") List<String> ids);

    /**
     * Search the users for all users whose email or name matches the query.
     * @param query The query string to search for
     * @param max Max number of results to return
     * @return The list of users that match the query
     */
    @GET(SEARCH_USERDETAILS_PATH)
    Call<List<UserDetails>> searchUserDetails(@Query("q") String query, @Query("max") int max);

    /**
     * Return all the UserDetails.  This will be super slow probably so caching the result is advised.
     *
     * @return A call that returns all the UserDetails.
     */
    @Deprecated
    @POST(GET_USER_LIST_FULL_PATH)
    Call<List<UserDetails>> getUserListFull();

    /**
     * Return a map of User email to User display name.  Returns all known users.
     *
     * @return A map of User email to User display name
     */
    @Deprecated
    @POST(GET_USER_LIST_PATH)
    Call<Map<String, String>> getUserList();

    /**
     * Return a map of User numeric id to User display name.  Returns all known users.
     *
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
        /**
         * The Call.Factory to use for calling the web services.  Most of the time this will be an OkHttpClient but
         * this accepts a Call.Factory to allow the OkHttpClient to be proxied via a Call.Factory in order to allow
         * health checks and metrics gathering, for example.
         */
        private final okhttp3.Call.Factory callFactory;
        private final HttpUrl baseUrl;

        private Moshi moshi = null;

        /**
         * Create a Builder using an okHttpClient and String baseUrl.  The baseUrl will be
         * converted to an HttpUrl and a trailing / will be added if required.
         *
         * @param callFactory The call factory to use (usually an {@link okhttp3.OkHttpClient})
         * @param baseUrl      The base URL of the User Details service
         */
        public Builder(okhttp3.Call.Factory callFactory, String baseUrl) {
            this.callFactory = callFactory;
            if (!baseUrl.endsWith("/")) {
                log.warning("User Details Client Base URL (" + baseUrl + ") does not end with a /");
                baseUrl += "/";
            }
            this.baseUrl = HttpUrl.parse(baseUrl);
        }

        Moshi defaultMoshi() {
            return new Moshi.Builder().add(Date.class, new Rfc3339DateJsonAdapter().nullSafe()).build();
        }

        /**
         * Create the UserDetailsClient instance.  If a moshi instance is not supplied, one will
         * be created.
         *
         * @return A UserDetailsClient using the supplied okhttpclient, baseUrl and moshi.
         */
        public UserDetailsClient build() {
            val moshi = this.moshi != null ? this.moshi : defaultMoshi();

            return new Retrofit.Builder()
                    .addConverterFactory(MoshiConverterFactory.create(moshi))
                    .callFactory(callFactory)
                    .baseUrl(baseUrl)
                    .build()
                    .create(UserDetailsClient.class);
        }
    }

}
