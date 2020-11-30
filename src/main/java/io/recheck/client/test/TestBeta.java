package io.recheck.client.test;

import io.recheck.client.HammerJ;
import io.recheck.client.crypto.E2EEncryption;
import io.recheck.client.exceptions.*;
import io.recheck.client.model.UserKeyPair;
import org.json.JSONArray;
import org.json.JSONObject;
import org.web3j.crypto.Credentials;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;

public class TestBeta {
    public static void main(String[] args) throws GeneralSecurityException, InvalidPhraseException, ValidationException, IOException, EncodeDecodeException, ServerException, KeyExchangeException, ExternalKeyPairException {
        HammerJ hammerJ = new HammerJ();
        E2EEncryption e2EEncryption = new E2EEncryption();
        String baseUrl = "http://xlw-prod-55.xl-websolutions.nl:3000";
        String network = "eth";
//        String baseUrl = "https://beta.recheck.io";
        hammerJ.init(baseUrl, "eth");
//        e2EEncryption.setNetwork("ae");
        e2EEncryption.setBaseUrl(baseUrl);
        e2EEncryption.setRequestId("cirdax-101");
        LogManager.getLogManager().reset();
        hammerJ.LOGGER.setLevel(Level.SEVERE);
//        Credentials credentials = Credentials.create("0x7c75bcf5fd660de667dcce42574ceb06eaf307916389c1a85fd5d41fe52ebc32");

//        String publicSignKey = credentials.getEcKeyPair().getPublicKey().toString(16);

//        UserKeyPair keyPair = new UserKeyPair("0x4d65b95f651282bae0554d429b3a2d93310541e2","ZV9UtRXPZkEpvirhdaFQHTJUonG7EySrd4JsqQqsmHZc66UH6","7c75bcf5fd660de667dcce42574ceb06eaf307916389c1a85fd5d41fe52ebc32", publicSignKey, "0x7c75bcf5fd660de667dcce42574ceb06eaf307916389c1a85fd5d41fe52ebc32", "" );

//
//        System.out.println("tva " + keyPair.getAddress());
//        String result = hammerJ.store("daaaaaata","neshto",".txt",keyPair);
//        System.out.println("toz rez " + result);

//        JSONObject js = new JSONObject(result);
//        JSONObject res = hammerJ.openFile("0x2331968c85a38e8aaf8d09536d056f2b5f9a4bbc29f20cd63224215f276b6c98", keyPair);
//        System.out.println("ress " + res.toString());

        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.SEVERE);
        hammerJ.LOGGER.addHandler(handler);

//        String passphrase = "m's folio blinn tuft layup chili felix why mitre beep gino medley";
        String passphrase = "m's folio blinn tuft layup chili felix why mitre beep gino daka";
        UserKeyPair keyPair = hammerJ.generateNewKeyPair(passphrase);
        String token = hammerJ.login(keyPair,"");
        e2EEncryption.setToken(token);
        String ch="";

        String recipient = "ak_25ZrFQDCAHoGVnT8Ed3hXgWwPwy7jpcQVtfs63DwEAYW6m6vgU";
        String recipientMail = "vampireskooo@gmail.com";
        String fileChainID = "0xd57f03fb24b0ee160eafcb54b4d939d752d372f216b1577f87cec6ffc8242963";


//        UserKeyPair keys = null;
//        keys = hammerJ.generateNewKeyPair(passphrase);

        //login
//        showKeys(keyPair);
//        hammerJ.login(keys,ch);

        //open
        JSONObject jss = hammerJ.openFile("0x64a55f81804340c0d6393a8a1d99829e3ec9641806ce8cb57bc1a10ef78f0bba",keyPair);
//        System.out.println(jss.toString(1));

        //check data
        JSONObject jsss = e2EEncryption.checkData(jss.get("payload").toString(), "cirdax");
        System.out.println(jsss.toString());
//        String directory = "downloads/";
//        hammerJ.downloadFileWithExternalID("DaakaTest", keys, directory);

        //checkHash
//        JSONObject js = hammerJ.checkHash(fileChainID,keys.getAddress());
//        System.out.println(js.toString(1));

//        share
//        JSONObject jss = hammerJ.shareData(fileChainID, recipientMail, keys);
//        System.out.println(jss.toString(1));

//        upload
//        String data = "masdasdsamamuddaaddd";
//        String fileContent = Base64.getEncoder().encodeToString(data.getBytes());
//
//        String s = hammerJ.store(fileContent,"test",".txt", keyPair);
//        System.out.println(s);
//        JSONArray js = new JSONArray(s);
//        for(int i =0;i<js.length();i++){
//            System.out.println(js.getJSONObject(i).toString());
//        }


        //sign
//        JSONObject js = hammerJ.signFile(fileChainID,keys.getAddress(),keys);
//        System.out.println(js.toString());

//         execSelection for open share and open selection
//                ArrayList<ResultFileObj> res = hammerJ.execSelection("sh:0xbdfe2f46dd93f32887a61151300956acda4f4cbc13ae80d4a6da6239965a2692", keys);
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