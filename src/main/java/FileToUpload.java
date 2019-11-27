public class FileToUpload {

    private String docId;
    private String docName;
    private String category;
    private String keywords;
    private String userId;
    private String payload;
    private Encryption encrypt;

    public Encryption getEncrypt() {
        return encrypt;
    }

    public void setEncrypt(Encryption encrypt) {
        this.encrypt = encrypt;
    }

    public String getDocId() {
        return docId;
    }

    public void setDocId(String docId) {
        this.docId = docId;
    }

    public String getDocName() {
        return docName;
    }

    public void setDocName(String docName) {
        this.docName = docName;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getKeywords() {
        return keywords;
    }

    public void setKeywords(String keywords) {
        this.keywords = keywords;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

}
