import com.iwebpp.crypto.TweetNaclFast;
import com.iwebpp.crypto.TweetNaclFast.Box;
import com.iwebpp.crypto.TweetNaclFast.Signature;
import com.lambdaworks.crypto.SCrypt;
import org.apache.commons.lang3.StringUtils;
import org.kocakosm.jblake2.Blake2s;
import org.web3j.crypto.Hash;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

import static com.iwebpp.crypto.TweetNaclFast.randombytes;
import static java.util.Arrays.copyOfRange;

/*
 Hash.sha3String(String a) is the equivalent to hash() / return '0x' + keccak256(src).toString('hex'); /
  in hammerJS
 */

public class App {
    public static final String BOX_NONCE = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";

    public static void main(String args[]) throws GeneralSecurityException, UnsupportedEncodingException {
        String passphrase = "clod sg grata image nelsen gsa bode boxy 1992 deacon keep free";
        String str = "Blake";
        String key = Base64.getEncoder().encodeToString(passphrase.getBytes());
        byte[] theNonce = TweetNaclFast.hexDecode(BOX_NONCE);
        // shared key

        encryptDataWithSymmetricKey(str, key);
//        String encodedString = Base64.getEncoder().encodeToString(str.getBytes());
//        byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
//        System.out.println("Encoded " + encodedString);
//        String decodedString = new String(decodedBytes);
//        System.out.println("Decoded " + decodedString);

//        String[] keys = generateAkKeyPair(passphrase);
//        System.out.println("public Enc" + keys[0]);
//        System.out.println("private Enc " + keys[1]);
//        System.out.println("public Sign " + keys[2]);
//        System.out.println("private Sign " + keys[3]);
//        System.out.println("phrase " + keys[4]);

    }

    //non-static method cannot be referenced from a static context
    private boolean sign(Signature signature, byte[] file, byte[] privateKey) {
        return signature.detached_verify(file, privateKey);
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

    private static int getRandomNumberInRange(int min, int max) {

        if (min >= max) {
            throw new IllegalArgumentException("max must be greater than min");
        }

        Random r = new Random();
        return r.nextInt((max - min) + 1) + min;
    }

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
        // byte[] encryptKeySeed = copyOfRange(derivedBytes, 0, 32);
        // byte[] signKeySeed = copyOfRange(derivedBytes, 32, 64);
    }

    private static UserKeyPair generateAkKeyPair(String passphrase) throws GeneralSecurityException {

        String key1 = "";
        String key2 = "";

        if ((passphrase != null) && (passphrase != "")) {
            passphrase = passphrase.trim();
            String[] words = StringUtils.split(passphrase);
            if (words.length < 12) {
                System.err.println("Invalid passphrase. Must be 12 words long.");
            }
            key1 = words[0] + " " + words[1] + " " + words[2] + " " + words[3] + " " + words[4] + " " + words[5];
            key2 = words[6] + " " + words[7] + " " + words[8] + " " + words[9] + " " + words[10] + " " + words[11];
        } else {
            String[] fullphrase = StringUtils.split(diceware());
            key1 = fullphrase[0] + " " + fullphrase[1] + " " + fullphrase[2] + " " + fullphrase[3] + " " + fullphrase[4] + " " + fullphrase[5];
            key2 = fullphrase[0] + " " + fullphrase[1] + " " + fullphrase[2] + " " + fullphrase[3] + " " + fullphrase[4] + " " + fullphrase[11];
        }
        String phrase = key1 + " " + key2;

        //gets the 64 byte for the creation of the two key pairs
        byte[] derivedBytes = session25519(key1, key2);

        //the first 32 bytes are used for the encryption pair, the second - sing pair.
        byte[] encryptKeySeed = copyOfRange(derivedBytes, 0, 32);
        byte[] signKeySeed = copyOfRange(derivedBytes, 32, 64);

        // creating a TweetNacl Box object for the encrypt pair
        Box.KeyPair keyPairSK = Box.keyPair_fromSecretKey(encryptKeySeed);
        String publicEncKey = Base58Check.encode(keyPairSK.getPublicKey());
        String privateEncKey = bytesToHex(keyPairSK.getSecretKey());

        // Having the second key pair TweetNacl Signature
        Signature.KeyPair keyPairS = TweetNaclFast.Signature.keyPair_fromSeed(signKeySeed);
        String publicSignKey = Base58Check.encode(keyPairS.getPublicKey());
        String privateSignKey = bytesToHex(keyPairS.getSecretKey());

        // put all the keys in the User keyPair's object
        UserKeyPair keys = new UserKeyPair(publicEncKey, privateEncKey, publicSignKey, privateSignKey,phrase);
        return keys;
    }

    private static String diceware() {
        RollDice rd = new RollDice();
        String phrase = rd.phrase();
        return phrase;
    }

    public EncryptedFile encryptFileToPublicKey(String fileData, String dstPublicKey) throws GeneralSecurityException, UnsupportedEncodingException {

        // create random object
        Random r = new Random();

        // create byte array
        byte[] bytesFileKey = new byte[32];
        byte[] bytesSaltKey = new byte[32];

        // put the next byte in the array
        r.nextBytes(bytesFileKey);
        r.nextBytes(bytesSaltKey);

        String fileKey = Base64.getEncoder().encodeToString(bytesFileKey);
        String salt = Base64.getEncoder().encodeToString(bytesSaltKey);

        System.out.println("fileKey " + fileKey);
        System.out.println("salt " + salt);

        String symKey = Base64.getEncoder().encodeToString((fileKey + salt).getBytes());
        System.out.println(symKey);

        String encryptedFile = encryptDataWithSymmetricKey(fileData, symKey);
        EncryptedDataWithPublicKey encryptedPass = encryptDataToPublicKeyWithKeyPair(fileKey, dstPublicKey);

        //Putting the data into a object data struct (JS like)
        EncryptedFile result = new EncryptedFile();
        result.setPayload(encryptedFile);
        result.getCredentials().setSyncPass(fileKey);
        result.getCredentials().setSalt(salt);
        result.getCredentials().setEncryptedPass(encryptedPass.getPayload());
        result.getCredentials().setEncryptedPubKey(encryptedPass.getSrcPublicEncKey());

        return result;

    }

    public boolean isEmptyStringArray(String[] array) {
        for (int i = 0; i < array.length; i++) {
            if (array[i] != null) {
                return false;
            }
        }
        return true;
    }

    public static String encryptDataWithSymmetricKey(String data, String key) throws UnsupportedEncodingException {
        // the key is encoded with Base64, otherwise the decoding won't work.
        byte[] keyUint8Array = Base64.getDecoder().decode(key);

        byte[] messageUint8 = data.getBytes();
        // random nonce
        int nonce = getRandomNumberInRange(0, 26000);

        // creating a Secret box object to cipher the data
        TweetNaclFast.SecretBox sb = new TweetNaclFast.SecretBox(keyUint8Array, nonce);
        byte[] cipher = sb.box(messageUint8);

        //gets the nonce into String, so that it can be converted into byte[]
        String nonceString = Integer.toString(nonce);
        byte[] nonceByte = nonceString.getBytes();

        // creating a new byte[] with the length of nonceByte and cipher, so that i can be packed into one variable
        int fullMessageLength = nonceByte.length + cipher.length;
        byte[] fullMessage = new byte[fullMessageLength];
        for (int i = 0; i < nonceByte.length; i++) {
            fullMessage[i] = nonceByte[i];
        }
        for (int i = nonceByte.length, p = 0; i < fullMessageLength; i++, p++) {
            fullMessage[i] = cipher[p];
        }

        String encodedFullMessage = Base64.getEncoder().encodeToString(fullMessage);
        return encodedFullMessage;
    }

    public String encrypt(String data, Box key) {

        byte[] theNonce = TweetNaclFast.hexDecode(BOX_NONCE);
        byte[] messageUint8 = data.getBytes();
        byte[] encrypted = key.after(messageUint8, theNonce.length,messageUint8.length,theNonce);

        // creating a new byte[] with the length of nonceByte and cipher, so that i can be packed into one variable
        int fullMessageLength = theNonce.length + encrypted.length;
        byte[] fullMessage = new byte[fullMessageLength];
        for (int i = 0; i < theNonce.length; i++) {
            fullMessage[i] = theNonce[i];
        }
        for (int i = theNonce.length, p = 0; i < fullMessageLength; i++, p++) {
            fullMessage[i] = encrypted[p];
        }

        String encodedFullMessage = Base64.getEncoder().encodeToString(fullMessage);
        return encodedFullMessage;
    }

    /**
     * @params EncryptedFile data
     *         UserProperties userProps - to have all of the needed properties
     * @return
     */

    public EncryptedDataWithPublicKey encryptDataToPublicKeyWithKeyPair(String data, String dstPublicEncKey, UserProperties userAkKeyPairs) throws GeneralSecurityException {
        if (userAkKeyPairs.getKeyPair() == null) {
            //passing a null variable to escape overloading the whole parameter
            String generate = null;
            userAkKeyPairs.setKeyPair(generateAkKeyPair(generate));
        }
        byte[] destPublicEncKeyArray = decodeBase58(dstPublicEncKey);
        byte[] mySecretEncKeyArray = decodeBase58(userAkKeyPairs.getKeyPair().getPrivateEncKey());
        // create BOX object to make the .before method
        TweetNaclFast.Box sharedKeyBox = new TweetNaclFast.Box(destPublicEncKeyArray, mySecretEncKeyArray);
        String encryptedData = encrypt(data, sharedKeyBox);

        //Putting the data into a object data struct (JS like)
        EncryptedDataWithPublicKey result = new EncryptedDataWithPublicKey();
        result.setPayload(encryptedData);
        result.setDstPublicEncKey(dstPublicEncKey);
        result.setSrcPublicEncKey(userAkKeyPairs.getKeyPair().getPublicEncKey());

        return result;
    }
    /**
     * @params EncryptedFile data,
     *
     * @return

     */
    public EncryptedDataWithPublicKey encryptDataToPublicKeyWithKeyPair(String data, String dstPublicEncKey) throws GeneralSecurityException {
        String generate = null;
        UserKeyPair srcAkPair = generateAkKeyPair(generate);
        byte[] destPublicEncKeyArray = decodeBase58(dstPublicEncKey);
        byte[] mySecretEncKeyArray = decodeBase58(srcAkPair.getPrivateEncKey());
        // create BOX object to make the .before method
        TweetNaclFast.Box sharedKeyBox = new TweetNaclFast.Box(destPublicEncKeyArray, mySecretEncKeyArray);
        String encryptedData = encrypt(data, sharedKeyBox);

        //Putting the data into a object data struct (JS like)
        EncryptedDataWithPublicKey result = new EncryptedDataWithPublicKey();
        result.setPayload(encryptedData);
        result.setDstPublicEncKey(dstPublicEncKey);
        result.setSrcPublicEncKey(srcAkPair.getPublicEncKey());

        return result;
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

    public FileToUpload getFileUploadData(FileObj fileObj, String userChainId, String userChainIdPubKey ) throws GeneralSecurityException, UnsupportedEncodingException {

        String fileContents = fileObj.getPayload();
        EncryptedFile encryptedFile = encryptFileToPublicKey(fileContents, userChainIdPubKey);
        String docOriginalHash = hashString(fileContents);
        String syncPassHash = hashString(encryptedFile.getCredentials().getSyncPass());
        String docChainId = hashString(docOriginalHash);

        FileToUpload upload = new FileToUpload();
        upload.setDocId(docChainId);
        upload.setDocName(fileObj.getName());
        upload.setCategory(fileObj.getCategory());
        upload.setKeywords(fileObj.getKeywords());
        upload.setUserId(userChainId);
        upload.setPayload(encryptedFile.getPayload());
        upload.getEncrypt().setDocHash(docOriginalHash);
        upload.getEncrypt().setSalt(encryptedFile.getCredentials().getSalt());
        upload.getEncrypt().setEncryptedPassA(encryptedFile.getCredentials().getEncryptedPass());
        upload.getEncrypt().setPubKeyA(encryptedFile.getCredentials().getEncryptedPubKey());

        return upload;

    }

    public String submitFile(EncryptedFile fileObj,UserProperties userProps, FileCredentials fileCredentials){

        return null;
    }
}
