package io.recheck.client;

public class Encryption {
    private String docHash;
    private String salt;
    private String passHash;
    private String encryptedPassA;
    private String pubKeyA;

    public String getDocHash() {
        return docHash;
    }

    public void setDocHash(String docHash) {
        this.docHash = docHash;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getPassHash() {
        return passHash;
    }

    public void setPassHash(String passHash) {
        this.passHash = passHash;
    }

    public String getEncryptedPassA() {
        return encryptedPassA;
    }

    public void setEncryptedPassA(String encryptedPassA) {
        this.encryptedPassA = encryptedPassA;
    }

    public String getPubKeyA() {
        return pubKeyA;
    }

    public void setPubKeyA(String pubKeyA) {
        this.pubKeyA = pubKeyA;
    }


}
