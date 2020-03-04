import io.recheck.client.App;
import io.recheck.client.UserKeyPair;
import org.json.JSONObject;
import org.web3j.crypto.Hash;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;

public class Test {
    private static String keccak256(String toHash) {
        return Hash.sha3String(toHash).replaceFirst("0x","");
    }
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String compressPubKey(BigInteger pubKey) {
        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
        String pubKeyHex = pubKey.toString(16);
        String pubKeyX = pubKeyHex.substring(0, 64);
        return pubKeyYPrefix + pubKeyX;
    }

    public static int byteArrayToLeInt(byte[] b) {
        final ByteBuffer bb = ByteBuffer.wrap(b);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        return bb.getInt();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] fromHexString(String src) {
        byte[] biBytes = new BigInteger("10" + src.replaceAll("\\s", ""), 16).toByteArray();
        return Arrays.copyOfRange(biBytes, 1, biBytes.length);
    }

    public static void main(String[] args){
        App ap = new App();

        LogManager.getLogManager().reset();
        ap.LOGGER.setLevel(Level.SEVERE);

        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.SEVERE);
        ap.LOGGER.addHandler(handler);

        String passphrase = "bode boxy 1992 deacon keep free clod sg grata image nelsen gsa";
//        String passphrase = "night hewitt stub ding tot viet heard hoi funny aver trout arrear";
//        String passphrase = "glum ouzo mike police linus remus chin bethel torch wail kenya cv";

        String ch="0x4eb93ba0bfdba1bdd619d309b55bdee2a01f472f60745d2c5cece20cd753a4d5";

        //communication-blockchain.pdf
        String doc = "0xfa6d14d20b01e40a0b6263df36bac171cbf27d4c648c7733fdd9e5de6406341b";

        UserKeyPair keys = null;
        try {
          keys = ap.generateAkKeyPair(passphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        login(ap,keys,ch);
        open(ap,doc, keys.getPublicSignKey(), keys);
//        Scanner sc = new Scanner(System.in);

        // String input
//        String selection = sc.nextLine();
        String selection= "s:0x2b1b9c5c1a24a1e77cb33a205f033ca80ca7cd8450940ed4852b945d85b7a402";
//        App.execSelection(selection, keys);
    }

    public void showKeys(UserKeyPair keys){
        System.out.println("address: " + keys.getAddress());
        System.out.println("public sign key: " + keys.getPublicSignKey());
        System.out.println("Private sign key: " + keys.getPrivateSignKey());
        System.out.println("Public enc key: " + keys.getPublicEncKey());
        System.out.println("Private enc key: " + keys.getPrivateEncKey());
        System.out.println("Phrase: "+ keys.getPhrase());
    }

    public static void login(App ap, UserKeyPair keys, String ch){
        ap.login(keys,ch);
    }
    public void upload(App ap, String userChainId, String userChainIdPubKey){

        JSONObject js = new JSONObject();
        byte[] array = new byte[0];
        String fileContent = "";
        try {
//            array = Files.readAllBytes(Paths.get("Greedy4.pdf"));
//            fileContent = Base64.getEncoder().encodeToString(array);
            fileContent = Base64.getEncoder().encodeToString("sdaaaasaaaaaa".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        js.put("payload", fileContent);
        js.put("name", "filenamed");
        js.put("category", "OTHER");
        js.put("keywords", "");

        String bl =  ap.store(js.get("name").toString(), js.get("payload").toString(), userChainId, userChainIdPubKey);

        System.out.println(bl);
    }
    public static void open(App ap, String doc, String userChainId, UserKeyPair keys){
        JSONObject jss = ap.openFile(doc,userChainId,keys);
        System.out.println(jss);
    }
}