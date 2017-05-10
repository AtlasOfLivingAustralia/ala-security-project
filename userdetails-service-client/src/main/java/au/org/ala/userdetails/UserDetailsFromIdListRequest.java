package au.org.ala.userdetails;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsFromIdListRequest implements Serializable {

    private static final long serialVersionUID = 327334009042532174L;

    private List<String> userIds;
    private boolean includeProps = false;
}
