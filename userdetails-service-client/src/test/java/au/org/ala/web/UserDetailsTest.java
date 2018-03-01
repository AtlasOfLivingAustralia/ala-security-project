package au.org.ala.web;

import org.junit.Test;
import static org.junit.Assert.*;

public class UserDetailsTest {

    @Test
    public void testMapProperties() {
        UserDetails userDetails = new UserDetails();
        final String city = "city";
        final String state = "state";
        final String organisation = "organisation";
        final String primaryUserType = "primaryUserType";
        final String secondaryUserType = "secondaryUserType";
        final String telephone = "telephone";

        userDetails.setPrimaryUserType(primaryUserType);
        userDetails.setSecondaryUserTypeProperty(secondaryUserType);
        userDetails.setOrganisation(organisation);
        userDetails.setCity(city);
        userDetails.setState(state);
        userDetails.setTelephone(telephone);

        assertTrue(userDetails.getPrimaryUserType().equals(primaryUserType));
        assertTrue(userDetails.getSecondaryUserType().equals(secondaryUserType));
        assertTrue(userDetails.getOrganisation().equals(organisation));
        assertTrue(userDetails.getCity().equals(city));
        assertTrue(userDetails.getState().equals(state));
        assertTrue(userDetails.getTelephone().equals(telephone));

        userDetails.setTelephone(telephone);
        userDetails.setState(state);
        userDetails.setCity(city);
        userDetails.setOrganisation(organisation);
        userDetails.setSecondaryUserTypeProperty(secondaryUserType);
        userDetails.setPrimaryUserType(primaryUserType);

        assertTrue(userDetails.getTelephone().equals(telephone));
        assertTrue(userDetails.getState().equals(state));
        assertTrue(userDetails.getCity().equals(city));
        assertTrue(userDetails.getOrganisation().equals(organisation));
        assertTrue(userDetails.getSecondaryUserType().equals(secondaryUserType));
        assertTrue(userDetails.getPrimaryUserType().equals(primaryUserType));
    }

}
