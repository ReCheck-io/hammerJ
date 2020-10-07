package io.recheck.client.model;

public class EncryptedDataWithPublicKey {
    private String payload;
    private String dstPublicEncKey;
    private String srcPublicEncKey;

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getDstPublicEncKey() {
        return dstPublicEncKey;
    }

    public void setDstPublicEncKey(String dstPublicEncKey) {
        this.dstPublicEncKey = dstPublicEncKey;
    }

    public String getSrcPublicEncKey() {
        return srcPublicEncKey;
    }

    public void setSrcPublicEncKey(String srcPublicEncKey) {
        this.srcPublicEncKey = srcPublicEncKey;
    }


}
