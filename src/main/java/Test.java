import io.recheck.client.App;
import io.recheck.client.UserKeyPair;
import org.json.JSONObject;
import org.web3j.crypto.Hash;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;

public class Test {
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

        //login
        ap.login(keys,ch);

        //open
//        JSONObject jss = ap.openFile(doc,keys.getPublicSignKey(),keys);
        String directory = "downloads/";
        ap.downloadFile(doc, keys, directory);
    }

    public void showKeys(UserKeyPair keys){
        System.out.println("address: " + keys.getAddress());
        System.out.println("public sign key: " + keys.getPublicSignKey());
        System.out.println("Private sign key: " + keys.getPrivateSignKey());
        System.out.println("Public enc key: " + keys.getPublicEncKey());
        System.out.println("Private enc key: " + keys.getPrivateEncKey());
        System.out.println("Phrase: "+ keys.getPhrase());
    }

    public void upload(App ap, String filename, String userChainId, String userChainIdPubKey){
        byte[] array;
        String fileContent = "";
        try {
            array = Files.readAllBytes(Paths.get("Greedy4.pdf"));
            fileContent = Base64.getEncoder().encodeToString(array);
//            fileContent = Base64.getEncoder().encodeToString("sdaaaasaaaaaa".getBytes());
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