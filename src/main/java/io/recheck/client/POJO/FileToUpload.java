package io.recheck.client.POJO;

public class FileToUpload {

    private String dataId;
    private String dataName;
    private String dataExtension;
    private String category = "OTHERS";
    private String keywords = "Daka";
    private String userId;
    private String payload;
    private io.recheck.client.POJO.Encryption encrypt;
    private String userChainId;
    private String requestId;
    private String requestType;
    private String requestBodyHashSignature;
    private String trailHash;
    private String trailHashSignatureHash;

    public String getDataExtension() {
        return dataExtension;
    }

    public void setDataExtension(String dataExtension) {
        this.dataExtension = dataExtension;
    }


    public String getUserChainId() {
        return userChainId;
    }

    public void setUserChainId(String userChainId) {
        this.userChainId = userChainId;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getRequestType() {
        return requestType;
    }

    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    public String getRequestBodyHashSignature() {
        return requestBodyHashSignature;
    }

    public void setRequestBodyHashSignature(String requestBodyHashSignature) {
        this.requestBodyHashSignature = requestBodyHashSignature;
    }

    public String getTrailHash() {
        return trailHash;
    }

    public void setTrailHash(String trailHash) {
        this.trailHash = trailHash;
    }

    public String getTrailHashSignatureHash() {
        return trailHashSignatureHash;
    }

    public void setTrailHashSignatureHash(String trailHashSignatureHash) {
        this.trailHashSignatureHash = trailHashSignatureHash;
    }

    public io.recheck.client.POJO.Encryption getEncrypt() {
        return encrypt;
    }

    public void setEncrypt(io.recheck.client.POJO.Encryption encrypt) {
        this.encrypt = encrypt;
    }

    public String getDataId() {
        return dataId;
    }

    public void setDataId(String dataId) {
        this.dataId = dataId;
    }

    public String getDataName() {
        return dataName;
    }

    public void setDataName(String dataName) {
        this.dataName = dataName;
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
