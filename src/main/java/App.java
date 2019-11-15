import com.iwebpp.crypto.TweetNaclFast;
import com.iwebpp.crypto.TweetNaclFast.Box;
import com.iwebpp.crypto.TweetNaclFast.Signature;
import com.lambdaworks.crypto.SCrypt;
import org.kocakosm.jblake2.Blake2s;
import org.web3j.crypto.Hash;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import static java.util.Arrays.copyOfRange;

/*
 Hash.sha3String(String a) is the equivalent to hash() / return '0x' + keccak256(src).toString('hex'); /
  in hammerJS
 */

public class App {
    public static final String BOX_NONCE = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";

    public static void main(String args[]) throws GeneralSecurityException {

        String key1 = "clod sg grata image nelsen gsa";
        String key2 = "bode boxy 1992 deacon keep free";

        byte[] derivedBytes = session25519(key1, key2);
        System.out.println("Hex derived bytes " + bytesToHex(derivedBytes).length());
        System.out.println("Hex encoding is " + bytesToHex(derivedBytes).toLowerCase());
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

    }

    //non-static method cannot be referenced from a static context
    private boolean sign(byte[] file, byte[] privateKey){
        return Signature.detached_verify(file, privateKey);
    }

    private String hashString(String toHash) {
        return Hash.sha3String(toHash);
    }

    private String encodeBase58(byte[] toEncode) throws NoSuchAlgorithmException {
        return Base58Check.encode(toEncode);
    }

    private byte[] decodeBase58(String toDecode) throws NoSuchAlgorithmException {
        return Base58Check.decode(toDecode);
    }

    // TODO: Whether this should stay an array or made into an object
    // For now it will be a string array having all info ... should be converted into object
    private static byte[] session25519(String key1, String key2) throws GeneralSecurityException {
        int logN = 131072;  // this number is 2^17  CPU/memory cost parameter (1 to 31)
        int r = 8;    // block size parameter
        int p = 1;   // Parallelization parameter.
        int dkLen = 64;   // length of derived key in Bytes

        // takes the first six words and encodes them with Blake2s
        byte[] key1Bytes = key1.getBytes();
        Blake2s key1Blake = new Blake2s(32); // A 32 Byte hash of the password
        key1Blake.update(key1Bytes);
        byte[] blakeHash = key1Blake.digest();

        // by definition, the second key is used as salt and need only be converted to byte[]
        byte[] key2Bytes = key2.getBytes();

        byte[] derivedBytes = SCrypt.scrypt(blakeHash, key2Bytes, logN, r, p, dkLen);

        return derivedBytes;

        // From the derivedBytes creating the seed for the following two key pairs
//        byte[] encryptKeySeed = copyOfRange(derivedBytes, 0, 32);
//        byte[] signKeySeed = copyOfRange(derivedBytes, 32, 64);
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
