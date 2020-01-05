import org.json.JSONObject;

import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Scanner;

public class Test {

    public static void main(String[] args){
        App ap = new App();
//        String passphrase = "clod sg grata image nelsen gsa bode boxy 1992 deacon keep free";
        String passphrase = "glum ouzo mike police linus remus chin bethel torch wail kenya cv";
        String userChainId = "ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5";
        String userChainIdPubKey = "2pYnhELKZnC4Ykg8YwE9zKRTnzcN2dbkNzFQhn6qR7fcmkoSZ5";
        String ch="0xd1a8e9d01667a8a4eb4b015318d6dceef808739ba5183e575d155c6a4646346a";
        String doc = "0x978c1c0bc5729e7b0753ae60440f201a66d6e96eb0666e75306d44e08a2153c8";

        UserKeyPair keys = null;
        try {
          keys = ap.generateAkKeyPair(passphrase);
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
        ap.login(keys,ch);

//       App.store(js.get("name").toString(), js.get("payload").toString(), userChainId, userChainIdPubKey);

//        JSONObject jss = App.openFile(doc,userChainId,keys);
//         App.decryptWithKeyPair(userChainId, doc, keys);

//        Scanner sc = new Scanner(System.in);

        // String input
//        String selection = sc.nextLine();
        String selection= "s:0x2b1b9c5c1a24a1e77cb33a205f033ca80ca7cd8450940ed4852b945d85b7a402";
//        App.execSelection(selection, keys);
    }
}
