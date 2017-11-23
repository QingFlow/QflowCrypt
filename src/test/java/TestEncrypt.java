import com.qflow.encrypt.EncInfoBean;
import com.qflow.encrypt.QflowAesException;
import com.qflow.encrypt.QflowCrypt;
import org.junit.Test;

public class TestEncrypt {
    @Test
    public void testEncDec() throws QflowAesException {
        // 先准备必要的信息
        String data = "中文可以吗";
        String nonce = "nonce";
        String aesKey = "6xth2mz84z2k9vsdiaodm8mhrfp9fcdvxglo1e2m937";
        String token = "xxxxxx";
        // new 一个加解密对象
        QflowCrypt qflowCrypt = new QflowCrypt(token, aesKey);
        // 加密
        EncInfoBean encInfoBean = qflowCrypt.EncryptMsg(data, nonce);

        //解密
        String decStr = qflowCrypt.DecryptMsg(encInfoBean.getSignature(),
                encInfoBean.getTimeStamp(),
                encInfoBean.getNonce(),
                encInfoBean.getData());

        System.out.println("解密后的内容为： " + decStr);
        assert decStr.equals(data);
    }
}
