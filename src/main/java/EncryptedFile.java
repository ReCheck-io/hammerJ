public class EncryptedFile {
    private String payload;
    private FileCredentials credentials;

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public FileCredentials getCredentials() {
        return credentials;
    }

    public void setCredentials(FileCredentials credentials) {
        this.credentials = credentials;
    }
}
