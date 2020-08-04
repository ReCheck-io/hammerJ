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

//        Public address: ak_2MAEj79xyD4KGfmgxEYav5GA4CSuFwPK7wgxZWFvwZukF1T7HA
//        Public signing key: ak_2MAEj79xyD4KGfmgxEYav5GA4CSuFwPK7wgxZWFvwZukF1T7HA
//        Private signing key: f86339d598b8ed062b146266ed30b374eaed13c6cc8c989c8f9bf90c352c6f50b1785b661ddccb7570ea5c62c26bc67ce5a5642c5c38d3b2914348118e87e1a9
//        Public encryption key: wYmEjRpjAhpSR358gg9ssbjbcMWuc1ST4ACthNBihyfUDiZ8k
//        Private encryption key: 0193ffaaf9c8cb59faf3fe9e7e6c811fccd08e591add55f2c49c1244d846f21d
//        Recovery phrase: culpa murre duane faith sweet locus derek rosen halo every islam horus

        String passphrase = "m's folio blinn tuft layup chili felix why mitre beep gino medley";

        String ch="0xd74ec98a98403c96089c463d1a3a0fdf6f6d98aaad389971194e77e15f5e30b6";


        String fileChainID = "0x8a26d491b66951db56d7edc14d5bdd6eb37b128deec3b88517b7dfd9f65dab7a";

        UserKeyPair keys = null;
        try {
          keys = hammerJ.newKeyPair(passphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        //login
        showKeys(keys);
        hammerJ.login(keys,ch);

        //open
//        JSONObject jss = hammerJ.openFile(fileChainID,keys);
//        String directory = "downloads/";
//        hammerJ.downloadFile(fileChainID, keys, directory);

        //upload
       String s = hammerJ.store("today.txt", keys);
        System.out.println(s);

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