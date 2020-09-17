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

        String passphrase = "m's folio blinn tuft layup chili felix why mitre beep gino medley";

        String ch="0xd7323d4eb25e57060f68f59640b06178ee81ea30b796f9653f9fa13e454b0b21";

        String recipient = "ak_25ZrFQDCAHoGVnT8Ed3hXgWwPwy7jpcQVtfs63DwEAYW6m6vgU";
        String recipientMail = "vampireskooo@gmail.com";
        String fileChainID = "0xd57f03fb24b0ee160eafcb54b4d939d752d372f216b1577f87cec6ffc8242963";

        UserKeyPair keys = null;
        keys = hammerJ.generateNewKeyPair(passphrase);

        //login
        showKeys(keys);
        hammerJ.login(keys,ch);

        //open
//        JSONObject jss = hammerJ.openFile(fileChainID,keys);
//        String directory = "downloads/";
//        hammerJ.downloadFile(fileChainID, keys, directory);

        //checkHash
//        JSONObject js = hammerJ.checkHash(fileChainID,keys.getAddress());
//        System.out.println(js.toString(1));

//        share
        JSONObject jss = hammerJ.shareData(fileChainID, recipientMail, keys);
        System.out.println(jss.toString(1));

        //upload
//       String s = hammerJ.store("today.txt", keys);
//        System.out.println(s);

        //sign
//        JSONObject js = hammerJ.signFile(fileChainID,keys.getAddress(),keys);
//        System.out.println(js.toString());

//         execSelection for open share and open selection
                ArrayList<ResultFileObj> res = hammerJ.execSelection("sh:0xbdfe2f46dd93f32887a61151300956acda4f4cbc13ae80d4a6da6239965a2692", keys);
                System.out.println(res.get(0).getDataId());
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