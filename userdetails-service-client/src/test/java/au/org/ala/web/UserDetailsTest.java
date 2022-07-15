package au.org.ala.web;

import org.junit.Test;
import static org.junit.Assert.*;

public class UserDetailsTest {

    @Test
    public void testMapProperties() {
        UserDetails userDetails = new UserDetails();
        final String city = "city";
        final String state = "state";
        final String country = "country";
        final String organisation = "organisation";

        userDetails.setOrganisation(organisation);
        userDetails.setCity(city);
        userDetails.setState(state);
        userDetails.setCountry(country);

        assertEquals(organisation, userDetails.getOrganisation());
        assertEquals(city, userDetails.getCity());
        assertEquals(state, userDetails.getState());
        assertEquals(country, userDetails.getCountry());

        userDetails.setCountry(country);
        userDetails.setState(state);
        userDetails.setCity(city);
        userDetails.setOrganisation(organisation);

        assertEquals(country, userDetails.getCountry());
        assertEquals(state, userDetails.getState());
        assertEquals(city, userDetails.getCity());
        assertEquals(organisation, userDetails.getOrganisation());
    }

}
