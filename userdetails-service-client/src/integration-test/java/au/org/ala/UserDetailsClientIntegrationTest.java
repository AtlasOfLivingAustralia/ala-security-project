package au.org.ala;

import au.org.ala.userdetails.UserDetailsFromIdListRequest;
import au.org.ala.userdetails.UserDetailsFromIdListResponse;
import au.org.ala.web.UserDetails;
import au.org.ala.userdetails.UserDetailsClient;
import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;
import org.assertj.core.api.Condition;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import retrofit2.Call;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

// Remove this and replace constants below to run the test against the actual service
@Ignore
public class UserDetailsClientIntegrationTest {

    // Replace these to run test
    static final String USER_ID = "0";
    static final String EMAIL = "replace@me";
    static final String DISPLAY_NAME = "Replace Me";

    OkHttpClient okHttpClient;
    UserDetailsClient userDetailsClient;

    @Before
    public void setup() {
        this.okHttpClient = new OkHttpClient.Builder().addInterceptor(new HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BODY)).build();
        this.userDetailsClient = new UserDetailsClient.Builder(okHttpClient, "https://auth.ala.org.au/userdetails/").build();
    }

    @Test
    public void testGetUserDetails() throws IOException {
        Call<UserDetails> userDetailsCall = userDetailsClient.getUserDetails(EMAIL, true);
        UserDetails userDetails = userDetailsCall.execute().body();
        assertThat(userDetails).isNotNull().hasFieldOrPropertyWithValue("displayName", DISPLAY_NAME).hasFieldOrPropertyWithValue("userName", EMAIL);
    }

    @Test
    public void testGetUserDetailsFromIdList() throws IOException {
        Call<UserDetailsFromIdListResponse> allUserDetailsCall = userDetailsClient.getUserDetailsFromIdList(new UserDetailsFromIdListRequest(Arrays.asList(USER_ID), true));
        UserDetailsFromIdListResponse userDetails = allUserDetailsCall.execute().body();
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.isSuccess()).isTrue();
        assertThat(userDetails.getUsers()).containsKeys(USER_ID);
        assertThat(userDetails.getUsers().get(USER_ID)).hasFieldOrPropertyWithValue("displayName", DISPLAY_NAME).hasFieldOrPropertyWithValue("userName", EMAIL).hasFieldOrPropertyWithValue("userId", USER_ID);
    }

    @Test
    public void testFailedGetUserDetailsFromIdList() throws IOException {
        Call<UserDetailsFromIdListResponse> allUserDetailsCall = userDetailsClient.getUserDetailsFromIdList(new UserDetailsFromIdListRequest(Arrays.asList(EMAIL), true));
        UserDetailsFromIdListResponse userDetails = allUserDetailsCall.execute().body();
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.isSuccess()).isFalse();
        assertThat(userDetails.getMessage()).isNotBlank();
    }

    @Test
    public void testGetUserListFull() throws IOException {
        Condition<String> onlyDigits = new Condition<String>() {

            @Override
            public boolean matches(String value) {
                try {
                    Long.parseLong(value);
                    return true;
                } catch (NumberFormatException e) {
                    return false;
                }
            }
        };
        Call<List<UserDetails>> listUserDetailsCall = userDetailsClient.getUserListFull();
        List<UserDetails> userDetailsList = listUserDetailsCall.execute().body();
        assertThat(userDetailsList).isNotNull().hasAtLeastOneElementOfType(UserDetails.class).first().hasFieldOrProperty("userName").hasFieldOrProperty("userId");
        assertThat(userDetailsList).extracting("userId", String.class).doesNotContainNull().are(onlyDigits);
    }

    @Ignore
    @Test
    public void testGetUserList() throws IOException {
        Call<Map<String, String>> userListCall = userDetailsClient.getUserList();
        Map<String, String> userList = userListCall.execute().body();
        assertThat(userList).isNotNull().containsEntry(EMAIL, DISPLAY_NAME);
    }

    @Ignore
    @Test
    public void testGetUserListWithIds() throws IOException {
        Call<Map<String, String>> userListWithIdsCall = userDetailsClient.getUserListWithIds();
        Map<String, String> userList = userListWithIdsCall.execute().body();
        assertThat(userList).isNotNull().containsValue(DISPLAY_NAME);
    }
}
