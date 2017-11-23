package com.qflow.encrypt;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.Arrays;

public class QflowCrypt {
    private static Charset CHARSET = Charset.forName("utf-8");
    private String token;
    private byte[] aesKey;
    private Base64 base64 = new Base64();

    /**
     * 构造函数
     * @param token 配置的token
     * @param encodingAesKey 配置的aesKey
     */
    public QflowCrypt(String token, String encodingAesKey) throws QflowAesException {
        if (encodingAesKey.length() != 43) {
            throw new QflowAesException(QflowAesException.IllegalAesKey);
        }
        this.token = token;
        aesKey = Base64.decodeBase64(encodingAesKey + "=");
    }


    /**
     * 对明文进行加密.
     *
     * @param text 需要加密的明文
     * @return 加密后base64编码的字符串
     */
    private String encrypt(String text) throws QflowAesException {
        // 获得最终的字节流, 未加密
        byte[] unencrypted = text.getBytes(CHARSET);

        try {
            // 设置加密模式为AES的CBC模式
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec iv = new IvParameterSpec(aesKey, 0, 16);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

            // 加密
            byte[] encrypted = cipher.doFinal(unencrypted);

            // 使用BASE64对加密后的字符串进行编码
            return base64.encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            throw new QflowAesException(QflowAesException.EncryptAESError);
        }
    }

    /**
     * 对密文进行解密.
     *
     * @param text 需要解密的密文
     * @return 解密得到的明文
     * @throws QflowAesException aes解密失败
     */
    private String decrypt(String text) throws QflowAesException {
        byte[] original;
        try {
            // 设置解密模式为AES的CBC模式
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key_spec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
            cipher.init(Cipher.DECRYPT_MODE, key_spec, iv);

            // 使用BASE64对密文进行解码
            byte[] encrypted = Base64.decodeBase64(text);

            // 解密
            original = cipher.doFinal(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            throw new QflowAesException(QflowAesException.DecryptAESError);
        }
        try {
            return new String(original, CHARSET);
        } catch (Exception e) {
            e.printStackTrace();
            throw new QflowAesException(QflowAesException.IllegalBuffer);
        }

    }

    /**
     * 外部使用方法，将数据打包（json)，将数据进行AES-CBC加密
     *
     * @param sendMsg 发送的数据，已经格式化的字符串
     * @param nonce 随机字符串
     *
     * @return 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的json格式的字符串
     */
    public EncInfoBean EncryptMsg(String sendMsg, String nonce) throws QflowAesException {
        // 加密
        String encStr = encrypt(sendMsg);

        // 生成安全签名
        String timeStamp = Long.toString(System.currentTimeMillis());

        String signature = SHA1.getSHA1(token, timeStamp, nonce, encStr);

        // 生成发送的json
        return new EncInfoBean(encStr, nonce, signature, timeStamp);
    }

    /**
     * 检验消息的真实性，并且获取解密后的明文.
     *
     * @param msgSignature 签名串，对应URL参数的msg_signature
     * @param timeStamp 时间戳，对应URL参数的timestamp
     * @param nonce 随机串，对应URL参数的nonce
     * @param postData 密文，对应POST请求的数据
     *
     * @return 解密后的原文
     */
    public String DecryptMsg(String msgSignature, String timeStamp, String nonce, String postData)
            throws QflowAesException {

        // 计算安全签名
        String signature = SHA1.getSHA1(token, timeStamp, nonce, postData);

        // 和URL中的签名比较是否相等
        if (!signature.equals(msgSignature)) {
            throw new QflowAesException(QflowAesException.ValidateSignatureError);
        }

        // 解密
        return decrypt(postData);
    }
}
