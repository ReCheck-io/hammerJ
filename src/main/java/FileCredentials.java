public class FileCredentials {
    private String syncPass;
    private String syncPassHash;
    private String salt;
    private String encryptedPass;
    private String encryptedPubKey;

    public String getSyncPassHash() {
        return syncPassHash;
    }

    public void setSyncPassHash(String syncPassHash) {
        this.syncPassHash = syncPassHash;
    }

    public String getSyncPass() {
        return syncPass;
    }

    public void setSyncPass(String syncPass) {
        this.syncPass = syncPass;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getEncryptedPass() {
        return encryptedPass;
    }

    public void setEncryptedPass(String encryptedPass) {
        this.encryptedPass = encryptedPass;
    }

    public String getEncryptedPubKey() {
        return encryptedPubKey;
    }

    public void setEncryptedPubKey(String encryptedPubKey) {
        this.encryptedPubKey = encryptedPubKey;
    }
}
