package au.org.ala.userdetails;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsFromIdListRequest {

    private List<String> userIds;
    private boolean includeProps = false;
}
