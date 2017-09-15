package au.org.ala.userdetails;

import au.org.ala.web.UserDetails;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsFromIdListResponse implements Serializable {

    private static final long serialVersionUID = -1565081443900911680L;
    //{"success":false,"message":"Exception: java.lang.NumberFormatException: For input string: \"simon.bear@csiro.au\""}
    /*
    "users": {
    "1":{
      "userId":"1",
      "userName":"user@email.address",
      "firstName":"User Given Name",
      "lastName":"User Surname",
      "email":"user@email.address",
      "locked": false,
      "props":{
        "secondaryUserType":"Citizen scientist",
        "organisation":"User Organisation",
        "telephone":"555-123456",
        "city":"User City",
        "state":"User State",
        "primaryUserType":"IT specialist"
      }
    }
  },
  "invalidIds":[2],
     */
    private boolean success;
    private String message;

    private Map<String, UserDetails> users = new HashMap<String, UserDetails>();
    private List<Integer> invalidIds = new ArrayList<Integer>();
}
