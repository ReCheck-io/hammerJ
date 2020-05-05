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

        //ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5
//        String passphrase = "bode boxy 1992 deacon keep free clod sg grata image nelsen gsa";

        //
         String passphrase = "night hewitt stub ding tot viet heard hoi funny aver trout arrear";
//        String passphrase = "glum ouzo mike police linus remus chin bethel torch wail kenya cv";
//        String passphrase = "samuel sane ry old ke crow peony lord sos lithe medley eliot";

        String ch="0xd74ec98a98403c96089c463d1a3a0fdf6f6d98aaad389971194e77e15f5e30b6";


        String fileChainID = "0x8a26d491b66951db56d7edc14d5bdd6eb37b128deec3b88517b7dfd9f65dab7a";

        UserKeyPair keys = null;
        try {
          keys = hammerJ.newKeyPair(passphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        //login
//        showKeys(keys);
        hammerJ.login(keys,ch);

        //open
//        JSONObject jss = hammerJ.openFile(fileChainID,keys);
        String directory = "downloads/";
        hammerJ.downloadFile(fileChainID, keys, directory);

        //upload
//        String s = hammerJ.store("tomorrow.txt", keys);
//        System.out.println(s);

//         execSelection for open share and open selection
//                ArrayList<ResultFileObj> res = hammerJ.execSelection("re:0xcea32931657083955965a6325463efccf6e86c0b1726a00e9af0b70e95fbffec", keys);
//                System.out.println(res.get(0).getDataId());
//
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