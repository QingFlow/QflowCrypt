package com.qflow.encrypt;

public class JsonParse {
    public static String generate(String data, String signature, String timeStamp, String nonce) {
        return "{\"data\":\"" + data +"\","
                + "\"signature\":\"" + signature +"\","
                + "\"timeStamp\":\"" + timeStamp + "\","
                + "\"nonce\":\"" + nonce + "\"}";

    }
}
