package io.recheck.client.model;

import org.json.JSONObject;

public class ResultFileObj {

    private String dataId;
    private JSONObject data;

    public ResultFileObj(String docId, JSONObject data){
        this.dataId = docId;
        this.data = data;
    }

    public String getDataId() {
        return dataId;
    }

    public void setDataId(String dataId) {
        this.dataId = dataId;
    }

    public JSONObject getData() {
        return data;
    }

    public void setData(JSONObject data) {
        this.data = data;
    }


}
