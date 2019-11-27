public class UserKeyPair {
    // The Enc keys are the normal public 32 bytes, the Sign are to be used with AEternity, for the moment.
    private String publicEncKey;
    private String privateEncKey;
    private String publicSignKey;
    private String privateSignKey;
    private String phrase;

    UserKeyPair(String publicEncKey, String privateEncKey, String publicSignKey, String privateSignKey, String phrase){
        setPublicEncKey(publicEncKey);
        setPrivateEncKey(privateEncKey);
        setPublicSignKey(publicSignKey);
        setPrivateSignKey(privateSignKey);
        setPhrase(phrase);
    }

    public String getPublicEncKey() {
        return publicEncKey;
    }

    public void setPublicEncKey(String publicEncKey) {
        this.publicEncKey = publicEncKey;
    }

    public String getPrivateEncKey() {
        return privateEncKey;
    }

    public void setPrivateEncKey(String privateEncKey) {
        this.privateEncKey = privateEncKey;
    }

    public String getPublicSignKey() {
        return publicSignKey;
    }

    public void setPublicSignKey(String publicSignKey) {
        this.publicSignKey = publicSignKey;
    }

    public String getPrivateSignKey() {
        return privateSignKey;
    }

    public void setPrivateSignKey(String privateSignKey) {
        this.privateSignKey = privateSignKey;
    }

    public String getPhrase() {
        return phrase;
    }

    public void setPhrase(String phrase) {
        this.phrase = phrase;
    }
}
