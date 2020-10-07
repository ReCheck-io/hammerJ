
import io.recheck.client.crypto.E2EEncryption;
import io.recheck.client.crypto.TweetNaclFast;
import io.recheck.client.exceptions.EncodeDecodeException;
import io.recheck.client.exceptions.InvalidPhraseException;
import io.recheck.client.model.UserKeyPair;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JUnitTesting {
    private E2EEncryption e2EEncryption = new E2EEncryption();

    @Test
    void generateAkKeyPairTestAE0() {
        e2EEncryption.setNetwork("ae");
        String passphrase ="";

        UserKeyPair keyPair = null;
        try {
            keyPair = e2EEncryption.newKeyPair(passphrase);
        } catch (GeneralSecurityException | InvalidPhraseException e) {
            e.printStackTrace();
        }

        String[] fullphrase = StringUtils.split(keyPair.getPhrase());
        assertEquals(fullphrase.length, 12, "Phrase words");
    }

    @Test
        //AEthernity keypair
    void generateAkKeyPairTestAE1() {
        e2EEncryption.setNetwork("ae");
        String passphrase = "bode boxy 1992 deacon keep free clod sg grata image nelsen gsa";
        String publicKey = "ak_ss3HAQPSjyMRHsmKfjwhHJNPFMq1ghouykb95teN61cVZ2kxj";
        String secretKey = "17f15e01dc1b1353384262ee7bdae6099133a2a1b60637e03086f22727c972be737d7663da2c742416788f15cbc8445a37a320016bf739ac71f679198d6a1e7e";
        String publicEncKey = "3rXZh5YEJ11GXNP37CUdaASTYEobKumXfVUmboUPtohfnfGik";
        String secretEncKey = "4be64e3e3e138fa220b08f29f4a2537ccbfa835fd3ca845d5290cd3b82665a84";
        String address = "";
        UserKeyPair keyPair = null;
        try {
            keyPair = e2EEncryption.newKeyPair(passphrase);
        } catch (GeneralSecurityException | InvalidPhraseException e) {
            e.printStackTrace();
        }
        assertEquals(keyPair.getPhrase(), passphrase, "Phrase");
        assertEquals(keyPair.getPublicSignKey(), publicKey, "Public Key");
        assertEquals(keyPair.getPrivateSignKey().toLowerCase(), secretKey.toLowerCase(), "Private Key");
        assertEquals(keyPair.getPublicEncKey(), publicEncKey, "Public Encryption Key");
        assertEquals(keyPair.getPrivateEncKey().toLowerCase(), secretEncKey.toLowerCase(), "Private Encryption Key");
//        assertEquals(keyPair.getAddress(),,"Address");

    }

    @Test
        //AEthernity keypair
    void generateAkKeyPairTestAE2() {
        e2EEncryption.setNetwork("ae");
        String passphrase = "glum ouzo mike police linus remus chin bethel torch wail kenya cv";
        String publicKey = "ak_hLrgbiSkiGZLmMgHBMWvX7LpxUB65rPyGm9ELsFpAMzrdLLsg";
        String secretKey = "8eebdbc922decfa6a8ce63bdfb81be3225e11ac525be4478fd7198657b2d5e265b9a2d399152e80850f765199f7b17b475edab4c00d24a7543723bfe1501e3c0";
        String publicEncKey = "pfa5gk3uMuSC9A83d6YWwhqP3SgjJfYs1P8pqpuEoLPDUd4h3";
        String secretEncKey = "57cb652c56e75276d2134983bf6c99df9e5cc8ade84343665ec4990551b83864";
        String address = "";
        UserKeyPair keyPair = null;
        try {
            keyPair = e2EEncryption.newKeyPair(passphrase);
        } catch (GeneralSecurityException | InvalidPhraseException e) {
            e.printStackTrace();
        }
        assertEquals(keyPair.getPhrase(), passphrase, "Phrase");
        assertEquals(keyPair.getPublicSignKey(), publicKey, "Public Key");
        assertEquals(keyPair.getPrivateSignKey().toLowerCase(), secretKey.toLowerCase(), "Private Key");
        assertEquals(keyPair.getPublicEncKey(), publicEncKey, "Public Encryption Key");
        assertEquals(keyPair.getPrivateEncKey().toLowerCase(), secretEncKey.toLowerCase(), "Private Encryption Key");
//        assertEquals(keyPair.getAddress(),,"Address");

    }

    @Test
    void generateAkKeyPairTestEth0() {
        e2EEncryption.setNetwork("eth");
        String passphrase ="";

        UserKeyPair keyPair = null;
        try {
            keyPair = e2EEncryption.newKeyPair(passphrase);
        } catch (GeneralSecurityException | InvalidPhraseException e) {
            e.printStackTrace();
        }

        String[] fullphrase = StringUtils.split(keyPair.getPhrase());
        assertEquals(fullphrase.length, 12, "Phrase words");
    }

    @Test //Ethereum account
    void generateAkKeyPairTestEth1() {
        e2EEncryption.setNetwork("eth");
        String publicAddress = "0x72a63e2b3ee7d45a88dfc374cb9261eca268dd36";
        String publicSigningKey = "1749f4f6bedf388813ec6741ae5d767f366169d0546770776be38ae914fe877593d54e3e76c8b9c6cab0d83d72dd6c338e26c4e5a2d1cd47c71b25a2a642d8e";
        String privateSigningKey = "0x10335fee7f708690faa74ac62a0262f4d40e1fd40425663093f5fa312c1a4cd0";
        String publicEncryptionKey = "2XHV1qZqoJojpwEGwkKjVt5LFaxED4Mw4hVrX7aJus1J4jSUBk";
        String privateEncryptionKey = "10335fee7f708690faa74ac62a0262f4d40e1fd40425663093f5fa312c1a4cd0";
        String passphrase ="night hewitt stub ding tot viet heard hoi funny aver trout arrear";

        UserKeyPair keyPair = null;
        try {
            keyPair = e2EEncryption.newKeyPair(passphrase);
        } catch (GeneralSecurityException | InvalidPhraseException e) {
            e.printStackTrace();
        }
        assertEquals(keyPair.getPhrase(), passphrase, "Phrase");
        assertEquals(keyPair.getPublicSignKey(), publicSigningKey, "Public Key");
        assertEquals(keyPair.getPrivateSignKey().toLowerCase(), privateSigningKey.toLowerCase(), "Private Key");
        assertEquals(keyPair.getPublicEncKey(), publicEncryptionKey, "Public Encryption Key");
        assertEquals(keyPair.getPrivateEncKey().toLowerCase(), privateEncryptionKey.toLowerCase(), "Private Encryption Key");
        assertEquals(keyPair.getAddress().toLowerCase(),publicAddress.toLowerCase(),"Address");

    }

    @Test //Ethereum account
    void generateAkKeyPairTestEth2() {
        e2EEncryption.setNetwork("eth");
        String publicAddress = "0x99cc18ec681542dcfc68657b4cc19df6060322a9";
        String publicSigningKey = "6538bcfbdb1d2149fb3be88c3eb68f5218e1f03141ef0de235f5ddba3418a4e244794ccbbd02b7b80d13819eaf0614b2857ee049adea83f71700eecbab96b642";
        String privateSigningKey = "0x763ab13116dd800b42371cdfc58057487e2ae887a573bc592b9399bb3702fb95";
        String publicEncryptionKey = "2GLhEyUHKV5Dsvna723bC86ZV8RkktJvXjYUQX3a7h7ad2yM6c";
        String privateEncryptionKey = "763ab13116dd800b42371cdfc58057487e2ae887a573bc592b9399bb3702fb95";
        String passphrase ="beggar naomi qb ck debris vita can't billow gumbo 6 roost scam";

        UserKeyPair keyPair = null;
        try {
            keyPair = e2EEncryption.newKeyPair(passphrase);
        } catch (GeneralSecurityException | InvalidPhraseException e) {
            e.printStackTrace();
        }
        assertEquals(keyPair.getPhrase(), passphrase, "Phrase");
        assertEquals(keyPair.getPublicSignKey(), publicSigningKey, "Public Key");
        assertEquals(keyPair.getPrivateSignKey().toLowerCase(), privateSigningKey.toLowerCase(), "Private Key");
        assertEquals(keyPair.getPublicEncKey(), publicEncryptionKey, "Public Encryption Key");
        assertEquals(keyPair.getPrivateEncKey().toLowerCase(), privateEncryptionKey.toLowerCase(), "Private Encryption Key");
        assertEquals(keyPair.getAddress().toLowerCase(),publicAddress.toLowerCase(),"Address");

    }

    //tests with encrypt/decrypt
    @Test
    void basicEncryption() throws EncodeDecodeException {
        e2EEncryption.setNetwork("ae");
        String message = "ei tui";
        String message2 = "mn0go m0lya v! m@d@M";

        byte[] mySecretEncKeyArray = e2EEncryption.hexStringToByteArray("584cfc583aab5bd84ab5947d49426fe76a4f2054a7ea4e6c3c2803108f2e4354");

        TweetNaclFast.Box.KeyPair kp = new TweetNaclFast.Box.KeyPair();
        kp = TweetNaclFast.Box.keyPair_fromSecretKey(mySecretEncKeyArray);

        TweetNaclFast.Box kpFromSecret = new TweetNaclFast.Box(kp.getPublicKey(),kp.getSecretKey());

        String firstEncryptedMessage = e2EEncryption.encryptData(message,kpFromSecret);
        String firstDecryptedMessage = e2EEncryption.decryptData(firstEncryptedMessage, kpFromSecret);

        String secondEncryptedMessage = e2EEncryption.encryptData(message2,kpFromSecret);
        String secondDecryptedMessage = e2EEncryption.decryptData(secondEncryptedMessage, kpFromSecret);

        assertEquals(message, firstDecryptedMessage, "First decrypted message");
        assertEquals(message2, secondDecryptedMessage, "Second decrypted message");

    }
    //tests with encryptDataWithSymmetricKey / decryptDataWithSymmetricKey
}
