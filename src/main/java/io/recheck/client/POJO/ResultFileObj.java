package io.recheck.client.POJO;

import org.json.JSONObject;

public class ResultFileObj {

    private String docId;
    private JSONObject data;

    public ResultFileObj(String docId, JSONObject data){
        this.docId = docId;
        this.data = data;
    }

    public String getDocId() {
        return docId;
    }

    public void setDocId(String docId) {
        this.docId = docId;
    }

    public JSONObject getData() {
        return data;
    }

    public void setData(JSONObject data) {
        this.data = data;
    }


}
