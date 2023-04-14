package au.org.ala.userdetails;


import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserStatsResponse implements Serializable {

    private static final long serialVersionUID = -5571343647860420043L;

//    {
//        "description": "'totalUsers' count excludes locked and non-activated accounts. 'totalUsersOneYearAgo' count is calculated from the 'created' date being earlier than 1 year from today.",
//            "totalUsers": 35658,
//            "totalUsersOneYearAgo": 26992
//    }

    private String description;
    private int totalUsers;
    private int totalUsersOneYearAgo;
}
