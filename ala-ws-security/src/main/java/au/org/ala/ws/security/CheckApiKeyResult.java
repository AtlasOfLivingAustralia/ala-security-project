package au.org.ala.ws.security;

public class CheckApiKeyResult {

    public CheckApiKeyResult() {
    }

    public CheckApiKeyResult(boolean valid, String userId, String email) {
        this.valid = valid;
        this.userId = userId;
        this.email = email;
    }

    public boolean getValid() {
        return valid;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    private boolean valid;
    private String userId;
    private String email;

    public static CheckApiKeyResult valid(String userId, String email) {
        return new CheckApiKeyResult(true, userId, email);
    }

    public static CheckApiKeyResult invalid() {
        return new CheckApiKeyResult(false, null, null);
    }
}
