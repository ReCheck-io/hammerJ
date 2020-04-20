import io.recheck.client.HammerJ;
import io.recheck.client.POJO.ResultFileObj;
import io.recheck.client.POJO.UserKeyPair;
import org.json.JSONObject;

import java.nio.file.Files;
import java.nio.file.Paths;
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


        String fileChainID = "0x14a17fe1b2bb8208ce045bec5830e7bfc800ca9d0fa600421916536495f19ccb";

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
//        JSONObject jss = hammerJ.openFile(fileChainID,keys);
        String directory = "downloads/";
        hammerJ.downloadFile(fileChainID, keys, directory);

        //upload
//        hammerJ.store("datatata.png", keys);

//         execSelection for open share and open selection
//                ArrayList<ResultFileObj> res = hammerJ.execSelection("sg:0xfcd15c61e7cce3fb5eaf7ac3f9b76646972a0e31bdac2f2db4389103aa9d1998", keys);
//                System.out.println(res.get(0).getDataId());

    }

    public static void showKeys(UserKeyPair keys){
        System.out.println("address: " + keys.getAddress());
        System.out.println("public sign key: " + keys.getPublicSignKey());
        System.out.println("Private sign key: " + keys.getPrivateSignKey());
        System.out.println("Public enc key: " + keys.getPublicEncKey());
        System.out.println("Private enc key: " + keys.getPrivateEncKey());
        System.out.println("Phrase: "+ keys.getPhrase());
    }

    public void execSelection(){
//        Scanner sc = new Scanner(System.in);
//        String selection = sc.nextLine();
//        String selection= "s:0x2b1b9c5c1a24a1e77cb33a205f033ca80ca7cd8450940ed4852b945d85b7a402";
//        App.execSelection(selection, keys);
    }
}