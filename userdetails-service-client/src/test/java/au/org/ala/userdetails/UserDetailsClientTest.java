package au.org.ala.userdetails;

import au.org.ala.web.UserDetails;
import com.google.common.collect.ImmutableMap;
import com.squareup.moshi.Moshi;
import com.squareup.moshi.Types;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import retrofit2.Call;
import retrofit2.Response;

import java.io.IOException;
import java.util.List;

import static au.org.ala.userdetails.UserDetailsClient.*;
import static com.google.common.collect.Lists.newArrayList;
import static com.google.common.collect.Sets.newHashSet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

public class UserDetailsClientTest {

    MockWebServer mockWebServer;
    Moshi moshi;
    UserDetailsClient userDetailsClient;

    static final UserDetails test = new UserDetails(1l, "Test", "Tester", "test@test.com", "test@test.com", "1", false, true, "Test Org", "City of Test", "TST", "country", newHashSet("ROLE_POTATO"));

    @Before
    public void setup() throws IOException {
        mockWebServer = new MockWebServer();

        Dispatcher dispatcher = new Dispatcher() {

            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                MockResponse response = new MockResponse();
                try {
                    String[] pathComponents = request.getPath().substring(1).split("\\?");
                    String path = pathComponents[0];

                    System.out.println("Path: " + path);
                    switch (path) {
                        case GET_USER_DETAILS_PATH:
                            response.setResponseCode(200).setBody(moshi.adapter(UserDetails.class).toJson(test));
                            break;
                        case GET_USER_DETAILS_FROM_ID_LIST_PATH:
                            UserDetailsFromIdListRequest body = moshi.adapter(UserDetailsFromIdListRequest.class).fromJson(request.getBody());
                            UserDetailsFromIdListResponse responseBody;
                            try {
                                for (String id : body.getUserIds()) {
                                    Integer.parseInt(id);
                                }
                                responseBody = new UserDetailsFromIdListResponse(true, "", ImmutableMap.of(test.getUserId(), test), newArrayList(123));
                            } catch (NumberFormatException e) {
                                // This is the same as the userdetails web service :S
                                responseBody = new UserDetailsFromIdListResponse(false, e.getMessage(), null, null);
                            }
                            response.setResponseCode(200).setBody(moshi.adapter(UserDetailsFromIdListResponse.class).toJson(responseBody));
                            break;
                        case GET_USER_DETAILS_BY_ROLE_PATH:
                            response.setResponseCode(200).setBody(moshi.adapter(Types.newParameterizedType(List.class, UserDetails.class)).toJson(newArrayList(test)));
                            break;
                        case GET_USER_LIST_FULL_PATH:
                            response.setResponseCode(200).setBody(moshi.adapter(Types.newParameterizedType(List.class, UserDetails.class)).toJson(newArrayList(test)));
                            break;
                        case GET_USER_STATS_PATH:
                            response.setResponseCode(200).setBody(moshi.adapter(UserStatsResponse.class).toJson(new UserStatsResponse("description", 2, 1)));
                            break;
                        case SEARCH_USERDETAILS_PATH:
                            response.setResponseCode(200).setBody(moshi.adapter(Types.newParameterizedType(List.class, UserDetails.class)).toJson(newArrayList(test)));
                            break;
                        case GET_USER_LIST_PATH:
                        case GET_USER_LIST_WITH_IDS_PATH:
                            // not implemented
                        default:
                            response.setResponseCode(404);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    response.setResponseCode(500).setBody(e.getMessage());
                }
                return response;
            }
        };
        mockWebServer.setDispatcher(dispatcher);
        mockWebServer.start();

        moshi = new Moshi.Builder().build();
        OkHttpClient client = new OkHttpClient.Builder().build();
        userDetailsClient = new UserDetailsClient.Builder(client, mockWebServer.url("/")).moshi(moshi).build();
    }

    @After
    public void teardown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    public void testGetUserDetails() throws IOException {
        Call<UserDetails> userDetailsCall = userDetailsClient.getUserDetails("test@test.com", true);
        Response<UserDetails> response = userDetailsCall.execute();

        assertThat(response.isSuccessful()).isTrue();

        UserDetails userDetails = response.body();
        assertThat(userDetails).isNotNull().isEqualTo(test);
    }

    @Test
    public void testGetAllUserDetails() throws IOException {
        UserDetailsFromIdListRequest request = new UserDetailsFromIdListRequest(newArrayList(test.getUserId(), "123"), true);
        Call<UserDetailsFromIdListResponse> call = userDetailsClient.getUserDetailsFromIdList(request);
        Response<UserDetailsFromIdListResponse> response = call.execute();

        assertThat(response.isSuccessful()).isTrue();

        UserDetailsFromIdListResponse usersDetails = response.body();

        assertThat(usersDetails).isNotNull();
        assertThat(usersDetails.isSuccess()).isTrue();
        assertThat(usersDetails.getInvalidIds()).contains(123);
        assertThat(usersDetails.getUsers()).contains(entry(test.getUserId(), test));
        assertThat(usersDetails.getUsers().get(test.getUserId()))
                .hasFieldOrPropertyWithValue("id", test.getId())
                .hasFieldOrPropertyWithValue("userId", test.getUserId())
                .hasFieldOrPropertyWithValue("firstName", test.getFirstName())
                .hasFieldOrPropertyWithValue("lastName", test.getLastName())
                .hasFieldOrPropertyWithValue("userName", test.getUserName())
                .hasFieldOrPropertyWithValue("locked", test.getLocked())
                .hasFieldOrPropertyWithValue("organisation", test.getOrganisation())
                .hasFieldOrPropertyWithValue("city", test.getCity())
                .hasFieldOrPropertyWithValue("state", test.getState())
                .hasFieldOrPropertyWithValue("country", test.getCountry())
                .hasFieldOrPropertyWithValue("roles", test.getRoles())
                .hasFieldOrPropertyWithValue("props", test.getProps());
    }

    @Test
    public void testGetUsersByRole() throws IOException {
        Call<List<UserDetails>> usersCall = userDetailsClient.getUserDetailsByRole("ROLE_USER", false, newArrayList("test@test.com"));
        Response<List<UserDetails>> response = usersCall.execute();

        assertThat(response.isSuccessful()).isTrue();

        List<UserDetails> usersDetails = response.body();

        assertThat(usersDetails).isNotEmpty();
    }

    @Test
    public void testSearch() throws IOException {
        Call<List<UserDetails>> usersCall = userDetailsClient.searchUserDetails("test test", 10);
        Response<List<UserDetails>> response = usersCall.execute();

        assertThat(response.isSuccessful()).isTrue();

        List<UserDetails> usersDetails = response.body();

        assertThat(usersDetails).isNotEmpty();
    }

    @Test
    public void testGetAllUserDetailsWithInvalidId() throws IOException {
        UserDetailsFromIdListRequest request = new UserDetailsFromIdListRequest(newArrayList("test@test.com"), true);
        Call<UserDetailsFromIdListResponse> call = userDetailsClient.getUserDetailsFromIdList(request);
        Response<UserDetailsFromIdListResponse> response = call.execute();

        assertThat(response.isSuccessful()).isTrue();

        UserDetailsFromIdListResponse usersDetails = response.body();

        assertThat(usersDetails).isNotNull();
        assertThat(usersDetails.isSuccess()).isFalse();
        assertThat(usersDetails.getMessage()).isNotBlank();
    }

    @Test
    public void testGetFullList() throws IOException {
        Call<List<UserDetails>> call = userDetailsClient.getUserListFull();
        Response<List<UserDetails>> response = call.execute();

        assertThat(response.isSuccessful()).isTrue();

        List<UserDetails> userDetailsList = response.body();

        assertThat(userDetailsList).isNotNull().contains(test);
    }

    @Test
    public void testGetUserStats() throws IOException {
        Call<UserStatsResponse> call = userDetailsClient.getUserStats();
        Response<UserStatsResponse> response = call.execute();
        assertThat(response.isSuccessful()).isTrue();

        UserStatsResponse body = response.body();

        assertThat(body).isNotNull();
        assertThat(body.getDescription()).isEqualTo("description");
        assertThat(body.getTotalUsers()).isEqualTo(2);
        assertThat(body.getTotalUsersOneYearAgo()).isEqualTo(1);
    }

}
