
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JUnitTesting {
    private App ap = new App();

    @Test
        //AEthernity keypair
    void generateAkKeyPairTestAE1() {
        ap.setNetwork("ae");
        String passphrase = "bode boxy 1992 deacon keep free clod sg grata image nelsen gsa";
        String publicKey = "ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5";
        String secretKey = "43410906a8fe275712236f0976e7e6a7e57c02760370c5e79880064fc64729cb164941e8ee75a37b177ffd157a63f2d6b01ba5a1b2364a809db2aad915364d14";
        String publicEncKey = "2pYnhELKZnC4Ykg8YwE9zKRTnzcN2dbkNzFQhn6qR7fcmkoSZ5";
        String secretEncKey = "584cfc583aab5bd84ab5947d49426fe76a4f2054a7ea4e6c3c2803108f2e4354";
        String address = "";
        UserKeyPair keyPair = null;
        try {
            keyPair = ap.generateAkKeyPair(passphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        assertEquals(keyPair.getPhrase(), passphrase, "Phrase");
        assertEquals("ak_"+keyPair.getPublicSignKey(), publicKey, "Public Key");
        assertEquals(keyPair.getPrivateSignKey().toLowerCase(), secretKey.toLowerCase(), "Private Key");
        assertEquals(keyPair.getPublicEncKey(), publicEncKey, "Public Encryption Key");
        assertEquals(keyPair.getPrivateEncKey().toLowerCase(), secretEncKey.toLowerCase(), "Private Encryption Key");
//        assertEquals(keyPair.getAddress(),,"Address");

    }

    @Test
        //AEthernity keypair
    void generateAkKeyPairTestAE2() {
        ap.setNetwork("ae");
        String passphrase = "glum ouzo mike police linus remus chin bethel torch wail kenya cv";
        String publicKey = "ak_wnSecLhxY8fD88JDsQTSskHcahNhjEqBhifxYtYZUSP4fWW3v";
        String secretKey = "c0ae46e67ca1f88efa0be77749515edb2b869bbb6bd5fe7d10914083302c24c67c6481f253c693b03e23502df789286c0882b8711105e8af5ba703f99c0c492c";
        String publicEncKey = "yLa7yurFPguxS7pzrFt6XsybmsndE3JeHHPwUoPE8i88xAhXD";
        String secretEncKey = "67265d50f0e8881bde95e4ffdfc825432eb82d4ea7fea8cef64cee3dd12c4b3e";
        String address = "";
        UserKeyPair keyPair = null;
        try {
            keyPair = ap.generateAkKeyPair(passphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        assertEquals(keyPair.getPhrase(), passphrase, "Phrase");
        assertEquals("ak_"+keyPair.getPublicSignKey(), publicKey, "Public Key");
        assertEquals(keyPair.getPrivateSignKey().toLowerCase(), secretKey.toLowerCase(), "Private Key");
        assertEquals(keyPair.getPublicEncKey(), publicEncKey, "Public Encryption Key");
        assertEquals(keyPair.getPrivateEncKey().toLowerCase(), secretEncKey.toLowerCase(), "Private Encryption Key");
//        assertEquals(keyPair.getAddress(),,"Address");

    }

    @Test //Ethereum account
    void generateAkKeyPairTestEth() {
        ap.setNetwork("eth");
        String publicAddress = "0xFbC5af5F69b2CA77C43190d58F75A47574F38187";
        String publicSigningKey = "13c6f2b1c6ba3c1dc6e6a51fdee08bb26e18e72a4ba608991193364e6f78609a06383e0d44d1db5d6de78d107b00d8d7bffcaf5d77f8f6a6ff83c6735ae60c0a";
        String privateSigningKey = "0xd16ab98dcdf2bdb2538b069f14da5ec6c057c10e058ba6a439dd3ea59e6259ba";
        String publicEncryptionKey = "mQURuMzyH1VQv4ZYab2kb8cnsU7jg4nQQBoFvEoCbYL3SWJ6V";
        String privateEncryptionKey = "d16ab98dcdf2bdb2538b069f14da5ec6c057c10e058ba6a439dd3ea59e6259ba";
        String passphrase ="night hewitt stub ding tot viet heard hoi funny aver trout arrear";

        UserKeyPair keyPair = null;
        try {
            keyPair = ap.generateAkKeyPair(passphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        assertEquals(keyPair.getPhrase(), passphrase, "Phrase");
        assertEquals(keyPair.getPublicSignKey(), publicSigningKey, "Public Key");
        assertEquals(keyPair.getPrivateSignKey().toLowerCase(), privateSigningKey.toLowerCase(), "Private Key");
        assertEquals(keyPair.getPublicEncKey(), publicEncryptionKey, "Public Encryption Key");
        assertEquals(keyPair.getPrivateEncKey().toLowerCase(), privateEncryptionKey.toLowerCase(), "Private Encryption Key");
        assertEquals(keyPair.getAddress().toLowerCase(),publicAddress.toLowerCase(),"Address");

    }

}
