package io.recheck.client;

public class UserProperties {
    private String userID;
    private UserKeyPair keyPair;

    public String getUserID() {
        return userID;
    }

    private void setUserID(String userID) {
        this.userID = userID;
    }

    public UserKeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(UserKeyPair keyPair) {
        this.keyPair = keyPair;
    }
}
