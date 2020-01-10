import com.iwebpp.crypto.TweetNaclFast;
import com.iwebpp.crypto.TweetNaclFast.Box;
import com.iwebpp.crypto.TweetNaclFast.Signature;
import com.lambdaworks.crypto.SCrypt;
import okhttp3.*;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.kocakosm.jblake2.Blake2s;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.crypto.Credentials;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import static java.util.Arrays.copyOfRange;


/*
 Hash.sha3String(String a) is the equivalent to hash() / return '0x' + keccak256(src).toString('hex'); /
  in hammerJS
 */

public class App {
    private static String token = "";
    private static String requestId = "ReCheck";
    private static String network = "eth"; //ae or eth
    private static String baseUrl = "http://localhost:3000";
    public static UserKeyPair browserKeyPair = new UserKeyPair("", "", "", "", "");
    public static final String BOX_NONCE = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";


//    public static void main(String args[]) throws GeneralSecurityException {
//        String passphrase = "clod sg grata image nelsen gsa bode boxy 1992 deacon keep free";
//        String str = "Blake";
//        String key = Base64.getEncoder().encodeToString(passphrase.getBytes());
//        byte[] theNonce = TweetNaclFast.hexDecode(BOX_NONCE);
//        byte[] destPublicEncKeyArray = "2pYnhELKZnC4Ykg8YwE9zKRTnzcN2dbkNzFQhn6qR7fcmkoSZ5".getBytes();
//        byte[] mySecretEncKeyArray = hexStringToByteArray("584cfc583aab5bd84ab5947d49426fe76a4f2054a7ea4e6c3c2803108f2e4354");
//    }

    //non-static method cannot be referenced from a static context
    private byte[] sign(byte[] file, UserKeyPair kp) throws NoSuchAlgorithmException {
        Signature sig = new Signature(decodeBase58(kp.getPublicSignKey()), hexStringToByteArray(kp.getPrivateSignKey()));
        //sig.detached_verify(file, hexStringToByteArray(kp.getPrivateSignKey()));
        return sig.detached(file);
    }

    /**
     * @param toHash
     * @return sha3 hash with 0x
     */
    private String getHash(String toHash) {
        return Hash.sha3String(toHash);
    }

    /**
     * @param toHash
     * @return sha3 hash without 0x
     */
    private String keccak256(String toHash) {
        return Hash.sha3String(toHash).replaceFirst("0x", "");
    }

//    function getRequestHash(requestBodyOrUrl) {
//        let requestString = '';
//
//        if (typeof requestBodyOrUrl === "object") {
//            let orderedObj = {};
//            Object.keys(requestBodyOrUrl).sort().forEach(function (key) {
//                switch (key) {
//                    case'payload':
//                        orderedObj[key] = '';
//                        break;
//                    case'requestBodyHashSignature':
//                        orderedObj[key] = 'NULL';
//                        break;
//                    default:
//                        orderedObj[key] = requestBodyOrUrl[key];
//                        break;
//                }
//            });
//
//            requestString = JSON.stringify(orderedObj).replace(/\s/g, "");
//        } else {
//            requestString = requestBodyOrUrl.replace(/([&|?]requestBodyHashSignature=)(.*?)([&]|$)/g, '$1NULL$3');
//        }
//
//        return getHash(requestString);
//    }

    /**
     * Gets a byte array and coverts it into String on the Base58 scheme.
     *
     * @param toEncode
     * @return Base58 encoded String
     * @throws NoSuchAlgorithmException
     */
    private String encodeBase58(byte[] toEncode) throws NoSuchAlgorithmException {
        return Base58Check.encode(toEncode);
    }

    /**
     * Takes a Base58 encoded String and returns a byte array.
     *
     * @param toDecode
     * @return
     * @throws NoSuchAlgorithmException
     */
    private byte[] decodeBase58(String toDecode) throws NoSuchAlgorithmException {
        return Base58Check.decode(toDecode);
    }

    /**
     * session25519 is a public key cryptography library for the generation of Curve25519 encryption and ed25519 digital signature keys.
     *
     * The encryption and signing keys are created with TweetNaCl.js, a port of TweetNaCl / NaCl.
     * The encryption keys are for the Public-key authenticated encryption box construction which implements
     * curve25519-xsalsa20-poly1305. The signing keys are for the ed25519 digital signature system.
     *
     * @param key1 - six random words concatenated into a String with a space delimiter
     * @param key2 - six random words concatenated into a String with a space delimiter
     * @return byte array that is going to be used for the creation of Sign and Encryption keys
     * @throws GeneralSecurityException
     */
    private byte[] session25519(String key1, String key2) throws GeneralSecurityException {
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

    /**
     *
     * @param passphrase - the secret 12 random words, which the user should be keeping secret and save in order to
     *                   recover their account in case something happens.
     *
     *                   In case this parameter is null or empty, it means that there is a new account to be created. It
     *                   happens by using diceware method to choose the random 12 words.
     *
     *                   It keyPair containing one address, public and private Sign keys,
     *                   public and private Encryption keys and the security phrase.
     *
     * @return UserKeyPair object, containing the important information.
     * @throws GeneralSecurityException
     */

    public UserKeyPair generateAkKeyPair(String passphrase) throws GeneralSecurityException {

        System.out.println("toz phrase " + passphrase);
        String key1 = "";
        String key2 = "";

        if ((passphrase != null) && !(passphrase.equals(""))) {
            passphrase = passphrase.trim();
            String[] words = StringUtils.split(passphrase);
            if (words.length != 12) {
                System.err.println("Invalid passphrase. Your input is " + words.length + " words. It must be 12 words long.");
                System.exit(0);
            }
            key1 = words[0] + " " + words[1] + " " + words[2] + " " + words[3] + " " + words[4] + " " + words[5];
            key2 = words[6] + " " + words[7] + " " + words[8] + " " + words[9] + " " + words[10] + " " + words[11];
        } else {
            String[] fullphrase = StringUtils.split(diceware());
            key1 = fullphrase[0] + " " + fullphrase[1] + " " + fullphrase[2] + " " + fullphrase[3] + " " + fullphrase[4] + " " + fullphrase[5];
            key2 = fullphrase[6] + " " + fullphrase[7] + " " + fullphrase[8] + " " + fullphrase[9] + " " + fullphrase[10] + " " + fullphrase[11];
        }
        String phrase = key1 + " " + key2;

        //gets the 64 byte for the creation of the two key pairs
        /**
         NB! IN ORDER FOR JAVA AND JS TO BE THE SAME, THE KEYS HERE ARE SWITCHED
         */
        byte[] derivedBytes = session25519(key2, key1);

        //the first 32 bytes are used for the encryption pair, the second - sing pair.
        byte[] encryptKeySeed = copyOfRange(derivedBytes, 0, 32);
        byte[] signKeySeed = copyOfRange(derivedBytes, 32, 64);


        // creating a TweetNacl Box object for the encrypt pair
        Box.KeyPair keyPairSK = Box.keyPair_fromSecretKey(encryptKeySeed);

        // Having the second key pair TweetNacl Signature
        Signature.KeyPair keyPairS = TweetNaclFast.Signature.keyPair_fromSeed(signKeySeed);

        String publicEncKey = Base58Check.encode(keyPairSK.getPublicKey());
        String privateEncKey = bytesToHex(keyPairSK.getSecretKey());

        String publicSignKey = null;
        String privateSignKey = null;
        String address = null;

        switch (network) {
            case "ae":
                publicSignKey = Base58Check.encode(keyPairS.getPublicKey());
                privateSignKey = bytesToHex(keyPairS.getSecretKey());
                address = publicSignKey;
                break;

            case "eth":
                privateSignKey = "0x" + bytesToHex(keyPairSK.getSecretKey());
                Credentials cs = Credentials.create(privateSignKey);

                publicSignKey = cs.getEcKeyPair().getPublicKey().toString(16);
                address = cs.getAddress();
                break;
        }

        // put all the keys in the User keyPair's object
        UserKeyPair keys = new UserKeyPair(address, publicEncKey, privateEncKey, publicSignKey, privateSignKey, phrase);
        return keys;
    }

    /**
     * This method is used to choose 12 random, easy to remember, words for a pass phrase. This phrase has to be saved by
     * the user on a save place, so that when something bad happens, they will be able to recover their account.
     *
     * @return String containing 12 words.
     */
    private String diceware() {
        RollDice rd = new RollDice();
        String phrase = rd.phrase();
        return phrase;
    }

    /**
     *
     * @param fileData
     * @param dstPublicKey
     * @return
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */
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

        String symKey = Base64.getEncoder().encodeToString(hexStringToByteArray(keccak256(fileKey + salt)));

        System.out.println(symKey);

        String encryptedFile = encryptDataWithSymmetricKey(fileData, symKey);
        EncryptedDataWithPublicKey encryptedPass = encryptDataToPublicKeyWithKeyPair(fileKey, dstPublicKey);

        //Putting the data into a object data struct (JS like)
        EncryptedFile result = new EncryptedFile();
        result.setPayload(encryptedFile);
        FileCredentials fc = new FileCredentials();
        fc.setSyncPass(fileKey);
        fc.setSalt(salt);
        fc.setEncryptedPass(encryptedPass.getPayload());
        fc.setEncryptedPubKey(encryptedPass.getSrcPublicEncKey());
        result.setCredentials(fc);

        return result;

    }

    /**
     *
     * @param data
     * @param key
     * @return
     * @throws UnsupportedEncodingException
     */
    public String encryptDataWithSymmetricKey(String data, String key) throws UnsupportedEncodingException {
        // the key is encoded with Base64, otherwise the decoding won't work.
        byte[] keyUint8Array = Base64.getDecoder().decode(key);
        byte[] nonceBytes = TweetNaclFast.makeSecretBoxNonce();
        byte[] messageUint8 = data.getBytes();

        // Creating the cipher (boxBytes) with key, message and nonce
        byte[] boxBytes = new TweetNaclFast.SecretBox(keyUint8Array).box(messageUint8, nonceBytes);

        // creating a new byte[] with the length of nonceByte and cipher, so that i can be packed into one variable
        int fullMessageLength = nonceBytes.length + boxBytes.length;
        byte[] fullMessage = new byte[fullMessageLength];
        for (int i = 0; i < nonceBytes.length; i++) {
            fullMessage[i] = nonceBytes[i];
        }
        for (int i = nonceBytes.length, p = 0; i < fullMessageLength; i++, p++) {
            fullMessage[i] = boxBytes[p];
        }

        String encodedFullMessage = Base64.getEncoder().encodeToString(fullMessage);
        return encodedFullMessage;
    }

    /**
     *
     * @param messageWithNonce
     * @param key
     * @return
     */
    public String decryptDataWithSymmetricKey(String messageWithNonce, String key) {

        byte[] keyUint8Array = Base64.getDecoder().decode(key);
        byte[] messageWithNonceAsUint8Array = Base64.getDecoder().decode(messageWithNonce);
        byte[] nonce = new byte[24];
        byte[] message = new byte[messageWithNonceAsUint8Array.length - nonce.length];

        // extracts the nonce
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = messageWithNonceAsUint8Array[i];
        }
        // extracts the message
        for (int i = nonce.length, p = 0; i < messageWithNonceAsUint8Array.length; i++, p++) {
            message[p] = messageWithNonceAsUint8Array[i];
        }

        byte[] decrypted = new TweetNaclFast.SecretBox(keyUint8Array).open(message, nonce);
        if (decrypted == null) {
            throw new Error("Decryption failed");
        }

        return new String(decrypted); //base64DecryptedMessage
    }

    /**
     * Takes as input secret or shared key and the data as a hash of type String that needs to be encrypted.
     * Using asymmetric public key encryption.
     *
     * Taken from TweetNaCl Box example
     * @param data String data payload
     * @param key Shared key - Box TweetNacl - that will be used for encryption of the data
     * @return
     */
    public String encrypt(String data, Box key) {

        byte[] theNonce = TweetNaclFast.hexDecode(BOX_NONCE);
        byte[] messageUint8 = data.getBytes();
        byte[] encrypted = key.after(messageUint8, 0, messageUint8.length, theNonce);

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

    public String decrypt(String messageWithNonce, Box key) {
        byte[] messageWithNonceAsUint8Array = Base64.getDecoder().decode(messageWithNonce);
        byte[] nonce = new byte[24];
        byte[] message = new byte[messageWithNonceAsUint8Array.length - nonce.length];
        int p = 0;
        for (int i = 0; i < 24; i++, p++) {
            nonce[i] = messageWithNonceAsUint8Array[i];
        }
        for (int i = 0; p < messageWithNonceAsUint8Array.length; i++, p++) {
            message[i] = messageWithNonceAsUint8Array[p];
        }

        byte[] decrypted = key.open(message, nonce);
        if (decrypted == null) {
            System.out.println("The decryption failed");
            System.exit(0);
        }
        String decryptedBase64Message = new String(decrypted);
        return decryptedBase64Message;
    }

    public EncryptedDataWithPublicKey encryptDataToPublicKeyWithKeyPair(String data, String dstPublicEncKey, UserKeyPair userAkKeyPairs) throws GeneralSecurityException {
        if (userAkKeyPairs == null) {
            //passing a null variable to escape overloading the whole parameter
            String generate = null;
            userAkKeyPairs = generateAkKeyPair(generate);
        }
        byte[] destPublicEncKeyArray = decodeBase58(dstPublicEncKey);
        byte[] mySecretEncKeyArray = hexStringToByteArray(userAkKeyPairs.getPrivateEncKey());
        // create BOX object to make the .before method
        TweetNaclFast.Box sharedKeyBox = new TweetNaclFast.Box(destPublicEncKeyArray, mySecretEncKeyArray);
        String encryptedData = encrypt(data, sharedKeyBox);

        //Putting the data into a object data struct (JS like)
        EncryptedDataWithPublicKey result = new EncryptedDataWithPublicKey();
        result.setPayload(encryptedData);
        result.setDstPublicEncKey(dstPublicEncKey);
        result.setSrcPublicEncKey(userAkKeyPairs.getPublicEncKey());

        return result;
    }

    public EncryptedDataWithPublicKey encryptDataToPublicKeyWithKeyPair(String data, String dstPublicEncKey) throws GeneralSecurityException {
        String generate = null;
        UserKeyPair srcAkPair = generateAkKeyPair(generate);

        byte[] destPublicEncKeyArray = decodeBase58(dstPublicEncKey);
        byte[] mySecretEncKeyArray = hexStringToByteArray(srcAkPair.getPrivateEncKey());

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

    public String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public FileToUpload getFileUploadData(FileObj fileObj, String userChainId, String userChainIdPubKey) throws GeneralSecurityException, UnsupportedEncodingException {

        String fileContents = fileObj.getPayload();
        EncryptedFile encryptedFile = encryptFileToPublicKey(fileContents, userChainIdPubKey);
        String docOriginalHash = getHash(fileContents);
        String syncPassHash = getHash(encryptedFile.getCredentials().getSyncPass());
        String docChainId = getHash(docOriginalHash);
        String requestType = "upload";
        String trailHash = getHash(docChainId + userChainId + requestType + userChainId);


        FileToUpload upload = new FileToUpload();
        upload.setUserId(userChainId);
        upload.setDocId(docChainId);
        upload.setRequestId(requestId);
        upload.setRequestType(requestType);
        upload.setRequestBodyHashSignature(null);
        upload.setTrailHash(trailHash);
        upload.setTrailHashSignatureHash(getHash(trailHash));
        upload.setDocName(fileObj.getName());
        if (fileObj.getCategory() == null) {
            upload.setCategory("OTHERS");
        }
        if (fileObj.getKeywords() == null) {
            upload.setKeywords("Daka");
        }
        upload.setUserId(userChainId);
        upload.setPayload(encryptedFile.getPayload());

        Encryption encrpt = new Encryption();

        encrpt.setDocHash(docOriginalHash);
        encrpt.setSalt(encryptedFile.getCredentials().getSalt());
        encrpt.setEncryptedPassA(encryptedFile.getCredentials().getEncryptedPass());
        encrpt.setPubKeyA(encryptedFile.getCredentials().getEncryptedPubKey());
        encrpt.setPassHash(syncPassHash);

        upload.setEncrypt(encrpt);

        return upload;

    }

    public final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    static OkHttpClient client = new OkHttpClient().newBuilder().connectTimeout(100, TimeUnit.SECONDS)
            .writeTimeout(100, TimeUnit.SECONDS)
            .readTimeout(300, TimeUnit.SECONDS)
            .build();

    private void init(String token, String baseUrl) {
        this.token = token;
        this.baseUrl = baseUrl;
    }

    //gets the challange and pass it down to another function to do the actual login, then callbacks it here
    public String login(UserKeyPair kp, String ch) {
        String getChallangeUrl = getEndpointUrl("login/challenge");
        String challangeResponce = getRequest(getChallangeUrl);
        JSONObject js = new JSONObject(challangeResponce);
        String challenge = js.get("challenge").toString();
        ch = ch.trim();
        if (ch.length() > 31) {
            challenge = ch;
        }
        System.out.println("challenge responce " + challangeResponce);
        return loginWithChallenge(challenge, kp);
    }

    private String loginWithChallenge(String challenge, UserKeyPair keyPair) {
        byte[] signature;
        try {
            signature = sign(challenge.getBytes(), keyPair);
            String sig58 = Base58Check.encode(signature);
            String pubEncKey = keyPair.getPublicSignKey();
            String pubKey = "ak_" + keyPair.getPublicSignKey();

            JSONObject payload = new JSONObject();

            payload.put("action", "login");
            payload.put("pubKey", pubKey);
            payload.put("pubEncKey", pubEncKey);
            payload.put("firebaseToken", "notoken");
            payload.put("challenge", challenge);
            payload.put("challengeSignature", sig58);

            String loginURL = getEndpointUrl("mobilelogin");
            String loginPostResult = post(loginURL, payload);
            JSONObject result = new JSONObject(loginPostResult);
            String tokenRes = result.get("rtnToken").toString();
            token = tokenRes;
            return tokenRes;
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return "Err";

    }

    private String getEndpointUrl(String action) {
        String url = baseUrl + "/" + action + "?noapi=1";
        if (!(token == null || token.trim() == "")) {
            url = baseUrl + "/" + action + "?api=1&token=" + token;
        }
        return url;
    }

    private String getEndpointUrl(String action, String appendix) {
        String url = baseUrl + "/" + action + "noapi=1";
        if (!(token == null && token.trim() == "")) {
            url = baseUrl + "/" + action + "?api=1&token=" + token;
        }
        if (!(appendix == null && appendix.trim() == "")) {
            System.out.println("toz apendics" + appendix);
            url = url + appendix;
        }
        return url;
    }

    private String getRequest(String url) {

        Request request = new Request.Builder()
                .url(url)
                .build();
        try (Response response = client.newCall(request).execute()) {
            return response.body().string();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private String post(String url, JSONObject json) throws IOException {
        RequestBody body = RequestBody.create(json.toString(), JSON);
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .build();
        try (Response response = client.newCall(request).execute()) {
            return response.body().string();
        }
    }

    private String uploadFile(FileToUpload file) throws IOException {
        JSONObject js = new JSONObject();
//        String token = "6ce48d47-70c5-4484-82ad-754adfa75294";
        js.put("docId", file.getDocId());
        js.put("docName", file.getDocName());
        js.put("category", file.getCategory());
        js.put("keywords", file.getKeywords());
        js.put("userId", file.getUserId());
        js.put("payload", file.getPayload());

        JSONObject encryption = new JSONObject();
        encryption.put("docHash", file.getEncrypt().getDocHash());
        encryption.put("salt", file.getEncrypt().getSalt());
        encryption.put("passHash", file.getEncrypt().getPassHash());
        encryption.put("encryptedPassA", file.getEncrypt().getEncryptedPassA());
        encryption.put("pubKeyA", file.getEncrypt().getPubKeyA());

        js.put("encryption", encryption);
        String responce = post("http://localhost:3000/uploadencrypted?api=1&token=" + token, js);
        return responce;
    }

    private JSONObject submitCredentials(String docChainId, String userChainId) {
        if (browserKeyPair.getPublicEncKey() == null) {
            try {
                browserKeyPair = generateAkKeyPair("");
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
        }
        System.out.println("Browser has key: " + browserKeyPair.getPublicSignKey());
        JSONObject browserPubKeySubmit = new JSONObject();

        browserPubKeySubmit.put("docId", docChainId);
        browserPubKeySubmit.put("userId", userChainId);

        JSONObject encryption = new JSONObject();
        encryption.put("pubKeyB", browserKeyPair.getPublicEncKey());

        browserPubKeySubmit.put("encryption", encryption);

        System.out.println("submit pubkey payload " + browserPubKeySubmit);

        String browserPubKeySubmitUrl = getEndpointUrl("browsercredentials");
        System.out.println("browser poll post submit pubKeyB " + browserPubKeySubmitUrl);

        String browserPubKeySubmitRes = null;
        try {
            browserPubKeySubmitRes = post(browserPubKeySubmitUrl, browserPubKeySubmit);
            JSONObject js = new JSONObject(browserPubKeySubmitRes);
            return js;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }


    }

    public String decryptDataWithPublicAndPrivateKey(String payload, String srcPublicEncKey, String secretKey) {
        byte[] srcPublicEncKeyArray = null;
        try {
            srcPublicEncKeyArray = decodeBase58(srcPublicEncKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] secretKeyArray = hexStringToByteArray(secretKey);
        TweetNaclFast.Box decryptedBox = new TweetNaclFast.Box(srcPublicEncKeyArray, secretKeyArray);
        return decrypt(payload, decryptedBox);//decrypted
    }

    public JSONObject decryptWithKeyPair(String userId, String docChainId, UserKeyPair keyPair) {
        System.out.println("User device requests decryption info from server " + docChainId + "  " + userId);
        String requestType = "download";
        String trailHash = getHash(docChainId + userId + requestType + userId);
        // TODO: fix this
        // String trailHashSignatureHash = getHash(signMessage(trailHash, keyPair.secretKey));
        // String query = "&userId="+ userId +"&docId=" + docChainId + "&requestId="+ requestId + "&requestType=" +requestType+ "&requestBodyHashSignature=NULL&trailHash="+ trailHash+ "&trailHashSignatureHash=" +trailHashSignatureHash;

        String getUrl = getEndpointUrl("exchangecredentials", "&userId=" + userId + "&docId=" + docChainId);
        System.out.println("decryptWithKeyPair get request " + getUrl);
        String serverEncryptionInfo = getRequest(getUrl);

        JSONObject serverEncrptInfo = new JSONObject(serverEncryptionInfo);
        JSONObject encrpt = new JSONObject(serverEncrptInfo.get("encryption").toString());

        System.out.println("toz encrpt" + encrpt.toString(1));
        System.out.println("Server responds to device with encryption info " + serverEncrptInfo);

        if (encrpt == null || encrpt.get("pubKeyB").toString() == null) {
            throw new Error("Unable to retrieve intermediate public key B.");
        }
        String decryptedPassword = decryptDataWithPublicAndPrivateKey(encrpt.get("encryptedPassA").toString(), encrpt.get("pubKeyA").toString(), keyPair.getPrivateEncKey());
        System.out.println("User device decrypts the sym password " + decryptedPassword);
        String syncPassHash = getHash(decryptedPassword);
        EncryptedDataWithPublicKey reEncryptedPasswordInfo = null;
        try {
            reEncryptedPasswordInfo = encryptDataToPublicKeyWithKeyPair(decryptedPassword, encrpt.get("pubKeyB").toString(), keyPair);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        System.out.println("User device re-encrypts password for browser " + reEncryptedPasswordInfo);

        JSONObject devicePost = new JSONObject();
        devicePost.put("docId", docChainId);
        devicePost.put("userId", "ak_" + keyPair.getPublicSignKey());

        JSONObject encryption = new JSONObject();
        encryption.put("syncPassHash", syncPassHash);
        encryption.put("encryptedPassB", reEncryptedPasswordInfo.getPayload());

        devicePost.put("encryption", encryption);

        System.out.println("devicePost " + devicePost);
        String postUrl = getEndpointUrl("exchangecredentials");
        System.out.println("decryptWithKeyPair post " + postUrl);

        String serverPostResponse = null;
        try {
            serverPostResponse = post(postUrl, devicePost);
        } catch (IOException e) {
            e.printStackTrace();
        }

        JSONObject serverResponse = new JSONObject(serverPostResponse);

        System.out.println("User device POST to server encryption info " + devicePost);
        System.out.println("Server responds to user device POST " + serverResponse.toString());
        return serverResponse;
    }

    private JSONObject processEncryptedFileInfo(JSONObject encryptedFileInfo, String devicePublicKey, String browserPrivateKey) {
        JSONObject encryption = new JSONObject(encryptedFileInfo.get("encryption").toString());
        System.out.println("ei toz encryption" + encryption);
        System.out.println("ei toz parametar" + encryptedFileInfo);
        String decryptedSymPassword = decryptDataWithPublicAndPrivateKey(encryption.get("encryptedPassB").toString(), devicePublicKey, browserPrivateKey);
        System.out.println("Browser decrypts sym password " + decryptedSymPassword);

        String fullPassword = Base64.getEncoder().encodeToString(hexStringToByteArray(keccak256(decryptedSymPassword + encryption.get("salt").toString())));
        System.out.println("Browser composes full password " + fullPassword);

        String decryptedFile = decryptDataWithSymmetricKey(encryptedFileInfo.get("payload").toString(), fullPassword);
        System.out.println("Browser decrypts the file with the full password " + decryptedFile);

        JSONObject resultFileInfo = encryptedFileInfo;
        resultFileInfo.put("payload", decryptedFile);
        resultFileInfo.put("encryption", "");
        return resultFileInfo;
    }

    private JSONObject validateFile(String fileContents, String userId, String docId) {
        String fileHash = getHash(fileContents);
        String validateUrl = getEndpointUrl("validate");

        JSONObject file = new JSONObject();
        file.put("userId", userId);
        file.put("docId", docId);

        JSONObject encryption = new JSONObject();
        encryption.put("decryptedDocHash", fileHash);

        file.put("encryption", encryption);

        String result = null;
        try {
            result = post(validateUrl, file);
        } catch (IOException e) {
            e.printStackTrace();
        }
        JSONObject res = new JSONObject(result);
        System.out.println(res.toString());
        if (res.toString() == null) {
            System.out.println("Unable to verify file.");
        } else {
            System.out.println("File contents validated.");
        }

        return res;
    }

    private JSONObject pollForFile(JSONObject credentialsResponse, String receiverPubKey) {
        if (credentialsResponse.get("userId").toString() != null) {
            String pollUrl = getEndpointUrl("docencrypted", "&userId=" + credentialsResponse.get("userId").toString() + "&docId=" + credentialsResponse.get("docId").toString());

            for (int i = 0; i < 50; i++) {
                String pollRes = getRequest(pollUrl);

                JSONObject pollResult = new JSONObject(pollRes);
                JSONObject encryption = new JSONObject(pollResult.get("encryption").toString());

                System.out.println("browser poll result " + pollResult.toString());

                if (encryption.toString() != null) {
                    System.out.println("Server responds to polling with " + pollResult.toString());
                    JSONObject decryptedFile = processEncryptedFileInfo(pollResult, receiverPubKey, browserKeyPair.getPrivateEncKey());
                    JSONObject validationResult = validateFile(decryptedFile.get("payload").toString(), decryptedFile.get("userId").toString(), decryptedFile.get("docId").toString());
                    System.out.println("toz validation" + validationResult.toString());
                    // TODO: Better check !
                    if (validationResult.toString() == null) {
                        return validationResult;
                    }
                    return decryptedFile;
                }
            }
            throw new Error("Polling timeout.");
        } else if (credentialsResponse.get("status").toString().equals("ERROR")) {
            throw new Error("Intermediate public key B submission error. Details: " + credentialsResponse.toString());
        } else {
            throw new Error("Server did not return userId. Details: " + credentialsResponse);
        }
    }

    private String getSelectedFiles(String selectionHash) {
        String getUrl = getEndpointUrl("selection", "&selectionHash=" + selectionHash);
        System.out.println("getSelectedFiles get request " + getUrl);
        String selectionResponse = getRequest(getUrl);
        System.out.println(selectionResponse);
        JSONObject selectionRes = new JSONObject(selectionResponse);

        System.out.println("toz selRes" + selectionRes.toString());

        return selectionRes.toString();
    }

    private JSONObject shareFile(String docId, String recipientId, UserKeyPair keyPair) {
        String getUrl = getEndpointUrl("shareencrypted", "&docId=" + docId + "&recipientId=" + recipientId);
        System.out.println("shareencrypted get request " + getUrl);
        String getShareResponse = getRequest(getUrl);
        System.out.println("Share res " + getShareResponse);

        JSONObject shareRes = new JSONObject(getShareResponse);


        if (shareRes.get("docId").toString().equals(docId)) {

            JSONObject encryption = new JSONObject(shareRes.get("encryption").toString());

            String recipientEncrKey = encryption.get("recipientEncrKey").toString();
            String encryptedPassA = encryption.get("encryptedPassA").toString();
            String pubKeyA = encryption.get("pubKeyA").toString();
            String decryptedPassword = decryptDataWithPublicAndPrivateKey(encryptedPassA, pubKeyA, keyPair.getPrivateEncKey());
            String syncPassHash = keccak256(decryptedPassword);
            EncryptedDataWithPublicKey reEncryptedPasswordInfo = null;
            try {
                reEncryptedPasswordInfo = encryptDataToPublicKeyWithKeyPair(decryptedPassword, recipientEncrKey, keyPair);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }

            JSONObject createShare = new JSONObject();
            createShare.put("docId", shareRes.get("docId").toString());
            createShare.put("userId", "ak_" + keyPair.getPublicSignKey());
            createShare.put("recipientId", shareRes.get("recipientId").toString());

            JSONObject encrpt = new JSONObject();
            encrpt.put("senderEncrKey", keyPair.getPublicEncKey());
            encrpt.put("syncPassHash", syncPassHash);
            encrpt.put("encryptedPassA", reEncryptedPasswordInfo.getPayload());

            createShare.put("encryption", encrpt);

            String postUrl = getEndpointUrl("shareencrypted");
            String serverPostResponse = null;
            try {
                serverPostResponse = post(postUrl, createShare);
            } catch (IOException e) {
                e.printStackTrace();
            }
            JSONObject postResponse = new JSONObject(serverPostResponse);

            System.out.println("Share POST to server encryption info " + createShare);
            System.out.println("Server responds to user device POST " + postResponse.toString());
            JSONObject result = new JSONObject(postResponse.toString());

            return result;
        }
        throw new Error("Unable to create share. Doc id mismatch.");
    }

    private String signMessage(String message, UserKeyPair keyPair) {
        switch (network) {
            case "ae":
                byte[] signatureBytes;
                try {
                    signatureBytes = sign((message).getBytes(), keyPair);
                    return encodeBase58(signatureBytes);// signatureB58;
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                break;

            case "eth":
                Credentials cs = Credentials.create(keyPair.getPrivateEncKey());
                byte[] msgHash = Hash.sha3(message.getBytes());
                Sign.SignatureData signature = Sign.signMessage(msgHash, cs.getEcKeyPair(), false);

                String v = bytesToHex(signature.getV());
                String r = Numeric.toHexString(signature.getR());
                String s = Numeric.toHexString(signature.getS()).replaceFirst("0x", "");

                String sig = r + s + v;
                return sig;
        }
        return "";
    }


    // End-functions

    /**
     * This function is going to be called upon uploading a document and 'store' it on the blockchain
     *
     * @param name              - this will be the name stored on the platform
     * @param content           - the content of the file
     * @param userChainId       - user's blockchain ID (in the AE blockchain this is ak_publicSignKey
     * @param userChainIdPubKey - user's publicEncKey
     * @return
     */
    public String store(String name, String content, String userChainId, String userChainIdPubKey) {
        FileObj obj = new FileObj();
        obj.setPayload(content);
        obj.setName(name);
        try {
            FileToUpload file = getFileUploadData(obj, userChainId, userChainIdPubKey);
            return uploadFile(file);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error. " + e.getMessage());
        }
        return null;
    }

    public JSONObject openFile(String docChainId, String userChainId, UserKeyPair keyPair) {

        JSONObject credentialsResponse = submitCredentials(docChainId, userChainId);
        JSONObject scanResult = decryptWithKeyPair(userChainId, docChainId, keyPair);
        if (scanResult.get("userId").toString() != null) {
            //polling server for pass to decrypt message
            return pollForFile(credentialsResponse, keyPair.getPublicEncKey());
        } else {
            throw new Error("Unable to decrypt file");
        }
    }

    public ArrayList<ResultFileObj> execSelection(String selection, UserKeyPair keyPair) {
        ArrayList<ResultFileObj> result = new ArrayList<>();
        // check if we have a selection or an id
        if (selection.indexOf(":") > 0) {

            String[] actionSelectionHash = selection.split(":");
            String action = actionSelectionHash[0];
            String selectionHash = actionSelectionHash[1];
            String selectionResult = getSelectedFiles(selectionHash);

            System.out.println("selection result " + selectionResult);

            JSONObject selectionRes = new JSONObject(selectionResult);
            System.out.println("--------");
            System.out.println(selectionRes.toString(1));
            System.out.println("-------");


            if (selectionRes.get("selectionHash").toString() != null) {

                String[] recipients = selectionRes.get("usersIds").toString().split(",");
                for (int i = 0; i < recipients.length; i++) {
                    recipients[i] = recipients[i].replace("[", "");
                    recipients[i] = recipients[i].replace("]", "");
                    recipients[i] = recipients[i].replace("\"", "");
                }

                String[] files = selectionRes.get("docsIds").toString().split(",");
                for (int i = 0; i < files.length; i++) {
                    files[i] = files[i].replace("[", "");
                    files[i] = files[i].replace("]", "");
                    files[i] = files[i].replace("\"", "");
                }

                if (recipients.length != files.length) {   // the array sizes must be equal
                    throw new Error("Invalid selection format.");
                }
                for (int i = 0; i < files.length; i++) {  // iterate open each entry from the array
                    if (action.equals("o")) {
                        if (keyPair.getPublicSignKey().equals(recipients[i])) {
                            System.out.println("selection entry omitted " + recipients[i] + ":" + files[i]);
                            continue;                             // skip entries that are not for that keypair
                        }
                        if (keyPair.getPrivateEncKey() != null) {
                            System.out.println("selection entry added " + recipients[i] + ":" + files[i]);
                            JSONObject fileContent = openFile(files[i], "ak_" + keyPair.getPublicSignKey(), keyPair);
                            result.add(new ResultFileObj(files[i], fileContent));
                        } else {
                            //creating the json object to pass to pollForFile
                            JSONObject fileCont = new JSONObject();
                            fileCont.put("docId", files[i]);
                            fileCont.put("userId", recipients[i]);

                            JSONObject fileContent = pollForFile(fileCont, keyPair.getPublicEncKey());

                            result.add(new ResultFileObj(files[i], fileContent));

                        }
                    } else if (action.equals("s")) {
                        JSONObject shareResult = shareFile(files[i], recipients[i], keyPair);

                        result.add(new ResultFileObj(files[i], shareResult));
                    } else if (action.equals("mo")) {
                        if (!("ak_" + keyPair.getPublicSignKey()).equals(recipients[i])) {
                            System.out.println("selection entry omitted " + recipients[i] + ":" + files[i]);
                            continue;                      // skip entries that are not for that keypair
                        }
                        System.out.println("selection entry added " + recipients[i] + ":" + files[i]);
                        JSONObject scanResult = decryptWithKeyPair(recipients[i], files[i], keyPair);

                        result.add(new ResultFileObj(files[i], scanResult));

                    } else {
                        throw new Error("Unsupported selection operation code.");
                    }
                }
            }
        } else {
            throw new Error("Missing selection operation code.");
        }
        return result;
    }
}
