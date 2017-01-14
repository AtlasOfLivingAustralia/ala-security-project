package au.org.ala.userdetails;

import au.org.ala.web.UserDetails;
import com.google.common.collect.ImmutableMap;
import com.squareup.moshi.Moshi;
import com.squareup.moshi.Types;
import okhttp3.HttpUrl;
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
import java.util.Collections;
import java.util.List;

import static au.org.ala.userdetails.UserDetailsClient.*;
import static com.google.common.collect.Lists.newArrayList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

public class UserDetailsClientTest {

    MockWebServer mockWebServer;
    Moshi moshi;
    UserDetailsClient userDetailsClient;

    static final UserDetails test = new UserDetails("Test", "Test", "test@test.com", "1", "test", "test", "test", "test", "test", "test", Collections.<String>emptySet());

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
                            AllUserDetailsRequest body = moshi.adapter(AllUserDetailsRequest.class).fromJson(request.getBody());
                            AllUserDetailsResponse responseBody;
                            try {
                                for (String id : body.getUserIds()) {
                                    Integer.parseInt(id);
                                }
                                responseBody = new AllUserDetailsResponse(true, "", ImmutableMap.of(test.getUserId(), test), newArrayList(123));
                            } catch (NumberFormatException e) {
                                // This is the same as the userdetails web service :S
                                responseBody = new AllUserDetailsResponse(false, e.getMessage(), null, null);
                            }
                            response.setResponseCode(200).setBody(moshi.adapter(AllUserDetailsResponse.class).toJson(responseBody));
                            break;
                        case GET_USER_LIST_FULL_PATH:
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
                } finally {
                    return response;
                }
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
        assertThat(userDetails).isNotNull().hasFieldOrPropertyWithValue("displayName", "Test Test").hasFieldOrPropertyWithValue("userName", "test@test.com");
    }

    @Test
    public void testGetAllUserDetails() throws IOException {
        AllUserDetailsRequest request = new AllUserDetailsRequest(newArrayList(test.getUserId(), "123"), true);
        Call<AllUserDetailsResponse> call = userDetailsClient.getUserDetailsFromIdList(request);
        Response<AllUserDetailsResponse> response = call.execute();

        assertThat(response.isSuccessful()).isTrue();

        AllUserDetailsResponse usersDetails = response.body();

        assertThat(usersDetails).isNotNull();
        assertThat(usersDetails.isSuccess()).isTrue();
        assertThat(usersDetails.getInvalidIds()).contains(123);
        assertThat(usersDetails.getUsers()).contains(entry(test.getUserId(), test));
    }

    @Test
    public void testGetAllUserDetailsWithInvalidId() throws IOException {
        AllUserDetailsRequest request = new AllUserDetailsRequest(newArrayList("test@test.com"), true);
        Call<AllUserDetailsResponse> call = userDetailsClient.getUserDetailsFromIdList(request);
        Response<AllUserDetailsResponse> response = call.execute();

        assertThat(response.isSuccessful()).isTrue();

        AllUserDetailsResponse usersDetails = response.body();

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

}
