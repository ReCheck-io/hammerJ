import org.json.JSONObject;

import java.security.GeneralSecurityException;
import java.util.Base64;

public class Test {

    public static void main(String[] args){
        String passphrase = "clod sg grata image nelsen gsa bode boxy 1992 deacon keep free";
        String userChainId = "ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5";
        String userChainIdPubKey = "2pYnhELKZnC4Ykg8YwE9zKRTnzcN2dbkNzFQhn6qR7fcmkoSZ5";
        String ch="0xf50ee08e484fbc8bae28c142d7de3fe0758c1d9276e88104cdaed58085471e35";
        String doc = "0x978c1c0bc5729e7b0753ae60440f201a66d6e96eb0666e75306d44e08a2153c8";

        UserKeyPair keys = null;
        try {
          keys = App.generateAkKeyPair(passphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        JSONObject js = new JSONObject();
        byte[] array = new byte[0];
        String fileContent = "";
        try {
//            array = Files.readAllBytes(Paths.get("Greedy4.pdf"));
//            fileContent = Base64.getEncoder().encodeToString(array);
            fileContent = Base64.getEncoder().encodeToString("sdaaasaaaaa".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        js.put("payload", fileContent);
        js.put("name", "filenamed");
        js.put("category", "OTHER");
        js.put("keywords", "");

        //login will either have a challenge from the browser QR, or will create a new one, without entering the browser GUI
        App.login(keys,ch);

//        App.store(js.get("name").toString(), js.get("payload").toString(), userChainId, userChainIdPubKey);

        App.openFile(doc,userChainId,keys);
//         App.decryptWithKeyPair(userChainId, doc, keys);
    }
}
