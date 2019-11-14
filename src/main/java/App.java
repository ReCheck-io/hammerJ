import com.iwebpp.crypto.TweetNaclFast;
import com.iwebpp.crypto.TweetNaclFast.*;
import com.lambdaworks.crypto.SCrypt;
import com.lambdaworks.crypto.SCryptUtil;
import org.kocakosm.jblake2.*;
import sun.nio.cs.StandardCharsets;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static java.util.Arrays.copyOfRange;

/**
 * key               = BLAKE2s(password) // A 32 Byte hash of the password
 * salt              = email
 * logN              = 17   // CPU/memory cost parameter (1 to 31)
 * r                 = 8    // block size parameter
 * dkLen             = 64   // length of derived key in Bytes
 * <p>
 * // Returns 64 Bytes of key material
 * derivedBytes      = scrypt(key, salt, logN, r, dkLen)
 * <p>
 * // Split the 64 Bytes of key material into two 32 Byte sub-arrays
 * encryptKeySeed    = derivedBytes[0, 32]
 * signKeySeed       = derivedBytes[32, 64]
 * <p>
 * keyPair           = nacl.box.keyPair.fromSecretKey(encryptKeySeed) // 32 Byte seed
 * signingKeyPair    = nacl.sign.keyPair.fromSeed(signKeySeed) // 32 Byte seed
 * <p>
 * <p>
 * let userKeyPair = {
 * publicKey: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
 * secretKey: '43410906a8fe275712236f0976e7e6a7e57c02760370c5e79880064fc64729cb164941e8ee75a37b177ffd157a63f2d6b01ba5a1b2364a809db2aad915364d14',
 * publicEncKey: '2pYnhELKZnC4Ykg8YwE9zKRTnzcN2dbkNzFQhn6qR7fcmkoSZ5',
 * secretEncKey: '584cfc583aab5bd84ab5947d49426fe76a4f2054a7ea4e6c3c2803108f2e4354',
 * phrase: 'bode boxy 1992 deacon keep free clod sg grata image nelsen gsa'
 * };
 */


public class App {
    public static final String BOX_NONCE = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
    private static int logN = 131072;  // this number is 2^17  CPU/memory cost parameter (1 to 31)
    private static int r = 8;    // block size parameter
    private static int p = 1;   // Parallelization parameter.
    private static int dkLen = 64;   // length of derived key in Bytes

    public static void main(String args[]) throws GeneralSecurityException {
        Box.KeyPair kp = Box.keyPair();
        kp = Box.keyPair_fromSecretKey(hexStringToByteArray("584cfc583aab5bd84ab5947d49426fe76a4f2054a7ea4e6c3c2803108f2e4354"));
        System.out.println("Public: " + Base58Check.encode(kp.getPublicKey()));
        System.out.println("Private: " + bytesToHex(kp.getSecretKey()).toLowerCase());

        Box.KeyPair kpBox = Box.keyPair();
        kp = Box.keyPair_fromSecretKey(hexStringToByteArray("584cfc583aab5bd84ab5947d49426fe76a4f2054a7ea4e6c3c2803108f2e4354"));
        Box box = new Box(kpBox.getPublicKey(), kpBox.getSecretKey());

        byte[] theNonce = TweetNaclFast.hexDecode(BOX_NONCE);
        byte[] message = "Message with TweetNacl encrypt".getBytes();
        byte[] cipher = box.box(message, theNonce);
        System.out.println(cipher);
        byte[] message2 = box.open(cipher, theNonce);
        System.out.println(message2);

        String s1 = new String(message);
        String s2 = new String(message2);

        System.out.println(s1 + "  " + s2);

        byte[] keyBlake = "bode boxy 1992 deacon keep free".getBytes();
        Blake2s keyBits = new Blake2s(32);
        keyBits.update(keyBlake);
        byte[] promenliva = keyBits.digest();

        System.out.println("Blake key is: " + bytesToHex(promenliva));
        String s3 = new String(keyBits.digest());
        System.out.println("WTF is :" + bytesToHex(promenliva));
        System.out.println("------------------------------");

        // IS THIS GOING TO WORK ?!
        // User 1 key phrase: 'bode boxy 1992 deacon keep free clod sg grata image nelsen gsa'

        byte[] key1 = "clod sg grata image nelsen gsa".getBytes();
        Blake2s key1Bytes = new Blake2s(32); // A 32 Byte hash of the password
        key1Bytes.update(key1);
        byte[] blakeHash = key1Bytes.digest();
        // System.out.println("Blake is" + key1Bytes.digest());
        // System.out.println("Blake keyyyy is " + bytesToHex(key1Bytes.digest()));

        byte[] key2 = "bode boxy 1992 deacon keep free".getBytes();

        // public static byte[] scrypt(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen)
        // Let "p" be 1,
        byte[] derivedBytes = SCrypt.scrypt(blakeHash, key2, logN, r, p, dkLen);
        System.out.println("Hex derived bytes " + bytesToHex(derivedBytes).length());
        System.out.println("Hex encoding is "+ bytesToHex(derivedBytes).toLowerCase());
        System.out.println("------------------------------");
        // Having the seed to the following two key pairs
        byte[] encryptKeySeed = copyOfRange(derivedBytes, 0, 32);
        byte[] signKeySeed = copyOfRange(derivedBytes, 32, 64);

        //should be 32 bytes
        System.out.println("encryptKeySeed " + encryptKeySeed.length);
        System.out.println("signKeySeed " + signKeySeed.length);
        System.out.println("------------------------------");
        // having the first BOX key pair
        Box.KeyPair keyPairSK = Box.keyPair_fromSecretKey(encryptKeySeed);
        System.out.println("Public Box user1 : " + Base58Check.encode(keyPairSK.getPublicKey()));
        System.out.println("Private Box user1: " + bytesToHex(keyPairSK.getSecretKey()));


        // Having the second key pair Signature
        Signature.KeyPair keyPairS = TweetNaclFast.Signature.keyPair_fromSeed(signKeySeed);
        System.out.println("Sign public user1 : " + Base58Check.encode(keyPairS.getPublicKey()));
        System.out.println("Sign secret user1: " + bytesToHex(keyPairS.getSecretKey()));
        System.out.println("------------------------------");
        // comparing byte arrays
        System.out.println("user1 key: " + bytesToHex(kp.getSecretKey()));
        System.out.println("user1 phrase: " + bytesToHex(keyPairSK.getSecretKey()));
        System.out.println("Comparison between the key from user1 and the key from user1's phrase "
                + Arrays.equals(kp.getSecretKey(), keyPairSK.getSecretKey()));
        //create account

    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}
