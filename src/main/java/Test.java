import io.recheck.client.HammerJ;
import io.recheck.client.POJO.ResultFileObj;
import io.recheck.client.POJO.UserKeyPair;

import java.security.GeneralSecurityException;
import java.util.*;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;

public class Test {
    public static void main(String[] args){
        HammerJ hammerJ = new HammerJ();

        LogManager.getLogManager().reset();
        hammerJ.LOGGER.setLevel(Level.SEVERE);

        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.SEVERE);
        hammerJ.LOGGER.addHandler(handler);

        String passphrase = "bode boxy 1992 deacon keep free clod sg grata image nelsen gsa";
//        String passphrase = "night hewitt stub ding tot viet heard hoi funny aver trout arrear";
//        String passphrase = "glum ouzo mike police linus remus chin bethel torch wail kenya cv";
//        String passphrase = "samuel sane ry old ke crow peony lord sos lithe medley eliot";

        String ch="0xa7fcc040fe0722ca2b5b25629cd2a02d7324efbc1fc4054605c909e84d4f9ce5";


        String doc = "0x37e206dc7411e1116f0949fd4f5851cad4d77215a43a2d8aecab981115026fbe";

        UserKeyPair keys = null;
        try {
          keys = hammerJ.newKeyPair(passphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        //login
        showKeys(keys);
        hammerJ.login(keys,ch);
//       ArrayList<ResultFileObj> res =  ap.execSelection("s:0xf3c0cd252f0c7071be812dd8bb1c44e928696e6fd587afb39e8499e04f7c5d3e", keys);
//       System.out.println(res.get(0).getDocId());

        //open
//        JSONObject jss = ap.openFile(doc,keys.getPublicSignKey(),keys);
//        String directory = "downloads/";
//        ap.downloadFile(res.get(0).getDocId(), keys, directory);

        //upload
//        upload(ap, "filefi", keys.getPublicSignKey(), keys.getPublicEncKey());

//         execSelection for open share and open selection
                ArrayList<ResultFileObj> res = hammerJ.execSelection("sg:0x04d284a516fd5a3bf4940cf3b7de2668d7296bdbd4cb8c2b8b9cd9f97aec0cf4", keys);
                System.out.println(res.get(0).getDataId());

    }

    public static void showKeys(UserKeyPair keys){
        System.out.println("address: " + keys.getAddress());
        System.out.println("public sign key: " + keys.getPublicSignKey());
        System.out.println("Private sign key: " + keys.getPrivateSignKey());
        System.out.println("Public enc key: " + keys.getPublicEncKey());
        System.out.println("Private enc key: " + keys.getPrivateEncKey());
        System.out.println("Phrase: "+ keys.getPhrase());
    }

    public static void upload(HammerJ ap, String filename, String userChainId, String userChainIdPubKey){
        byte[] array;
        String fileContent = "";
        try {
//            array = Files.readAllBytes(Paths.get("Greedy4.pdf"));
//            fileContent = Base64.getEncoder().encodeToString(array);
            fileContent = Base64.getEncoder().encodeToString("sdaaaasaaaaaaaaaaa".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        String upload =  ap.store(filename, fileContent, userChainId, userChainIdPubKey);

        System.out.println(upload);
    }
    public void execSelection(){
//        Scanner sc = new Scanner(System.in);
//        String selection = sc.nextLine();
//        String selection= "s:0x2b1b9c5c1a24a1e77cb33a205f033ca80ca7cd8450940ed4852b945d85b7a402";
//        App.execSelection(selection, keys);
    }
}