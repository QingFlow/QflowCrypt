package com.qflow.encrypt;

public class EncInfoBean {
    private String data;
    private String nonce;
    private String signature;
    private String timeStamp;

    public EncInfoBean() {
    }

    public EncInfoBean(String data, String nonce, String signature, String timeStamp) {
        this.data = data;
        this.nonce = nonce;
        this.signature = signature;
        this.timeStamp = timeStamp;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }
}
