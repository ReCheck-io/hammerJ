import org.json.JSONObject;

import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Scanner;

public class Test {

    public static void main(String[] args){
        String passphrase = "clod sg grata image nelsen gsa bode boxy 1992 deacon keep free";
        String userChainId = "ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5";
        String userChainIdPubKey = "2pYnhELKZnC4Ykg8YwE9zKRTnzcN2dbkNzFQhn6qR7fcmkoSZ5";
        String ch="0xcdf59e67c29790c84420bb4f4ce455e634c6e452d5e0b0cae43dcf3cca3d5d3a";
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

//       App.store(js.get("name").toString(), js.get("payload").toString(), userChainId, userChainIdPubKey);

//        JSONObject jss = App.openFile(doc,userChainId,keys);
//         App.decryptWithKeyPair(userChainId, doc, keys);

//        Scanner sc = new Scanner(System.in);

        // String input
//        String selection = sc.nextLine();
        String selection= "s:0x423061e18dc77cb77489180e0c5a4deb5349a597a2147ae7d9e55d07c153a4d7";
        App.execSelection(selection, keys);
    }
}
