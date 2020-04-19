package io.recheck.client.POJO;

public class FileObj {

    private String payload;
    private String name;
    private String category;
    private String keywords;
    private String dataExtention;


    public String getDataExtention() {
        return dataExtention;
    }

    public void setDataExtention(String dataExtention) {
        this.dataExtention = dataExtention;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCategory() {
        if (category == null) {
            category = " ";
        }
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getKeywords() {
        if (keywords == null) {
            keywords = " ";
        }
        return keywords;
    }

    public void setKeywords(String keywords) {
        this.keywords = keywords;
    }

}
