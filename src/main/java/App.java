import com.iwebpp.crypto.TweetNaclFast;
import com.iwebpp.crypto.TweetNaclFast.Box;
import com.iwebpp.crypto.TweetNaclFast.Signature;
import com.lambdaworks.crypto.SCrypt;
import okhttp3.*;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.kocakosm.jblake2.Blake2s;
import org.web3j.crypto.Hash;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import static java.util.Arrays.copyOfRange;
import static jdk.nashorn.internal.objects.NativeMath.log;

/*
 Hash.sha3String(String a) is the equivalent to hash() / return '0x' + keccak256(src).toString('hex'); /
  in hammerJS
 */

public class App {
    private static String token = "";
    private static String baseUrl = "http://localhost:3000";
//    private static String doc = "0x3fb9d3b44685884339f0d56f2ca1e8c08042cc598358d6c280342314a0ac2736";
    private static String doc =  "0x21b58ea9235e2abb89c47f2cee5b8eb7b80d7db2f9bdf4958886d0938b87a445";
    private static UserKeyPair browserKeyPair = new UserKeyPair("", "", "", "");
    public static final String BOX_NONCE = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";

    public static void main(String args[]) throws GeneralSecurityException {
        String passphrase = "clod sg grata image nelsen gsa bode boxy 1992 deacon keep free";
        String str = "Blake";
        String key = Base64.getEncoder().encodeToString(passphrase.getBytes());
        byte[] theNonce = TweetNaclFast.hexDecode(BOX_NONCE);
        byte[] destPublicEncKeyArray = "2pYnhELKZnC4Ykg8YwE9zKRTnzcN2dbkNzFQhn6qR7fcmkoSZ5".getBytes();
        byte[] mySecretEncKeyArray = hexStringToByteArray("584cfc583aab5bd84ab5947d49426fe76a4f2054a7ea4e6c3c2803108f2e4354");

//        TweetNaclFast.Box.KeyPair kp = new Box.KeyPair();
//        kp =Box.keyPair_fromSecretKey(mySecretEncKeyArray);
//        System.out.println("Public: " + Base58Check.encode(kp.getPublicKey()));
//        System.out.println("Private: " + bytesToHex(kp.getSecretKey()).toLowerCase());
//
//        TweetNaclFast.Box kpFromSecret = new TweetNaclFast.Box(kp.getPublicKey(),kp.getSecretKey());
//        System.out.println("kp shared key "+ Base58Check.encode(kpFromSecret.toString().getBytes()).length());
//        System.out.println("secret " + Base58Check.encode(kp.getSecretKey()));
//        System.out.println("kp key "+ Base58Check.encode(kpFromSecret.toString().getBytes()));
//
//        // shared key
//
//        /**
//         *  The case of encrypting something with Java and decrypt it with JS
//         *
//         *  Encrypted - aWlu6VW2K3PNYr2odfxz1oIZ4ANregs3krHLUmqe7chMJTTThULNy+u2Gvnk
//         *  Decrypted -
//         *
//         */
//        String encrypted = encrypt(str, kpFromSecret);
//        System.out.println("ei tva" +  encrypted);
//
//        /**
//         *  The case of encrypting something with JS and decrypt it with Java
//         *
//         *  Encrypted -
//         *  Decrypted -
//         *
//         */
//        encrypted = "UfNSxfa0xBxhkf5k/yRBC6ZjuVXxqJm1p68xXJkjtxuYl9re58k4vXRnHRgXczdZNg";
//        String decrypted = decrypt(encrypted, kpFromSecret);
//        System.out.println(decrypted);

//
//        try {
//            encryptDataWithSymmetricKey(str, key);
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        }
//        String encodedString = Base64.getEncoder().encodeToString(str.getBytes());
//        byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
//        System.out.println("Encoded " + encodedString);
//        String decodedString = new String(decodedBytes);
//        System.out.println("Decoded " + decodedString);

        UserKeyPair keys = generateAkKeyPair(passphrase);
//        System.out.println("public Enc " + keys.getPublicEncKey());
//        System.out.println("private Enc " + keys.getPrivateEncKey());
//        System.out.println("public Sign " + keys.getPublicSignKey());
//        System.out.println("private Sign " + keys.getPrivateSignKey());
//        System.out.println("phrase " + keys.getPhrase());

        /**
         * Testing the get URL stuff
         */
        System.out.print("gimme that challenge");
        Scanner scanner = new Scanner(System.in);

        // get their input as a String
//        String challenge = scanner.nextLine();
        String challenge = "0xb553fac3f69a111842c2d800e97cdeb740ac638e8d12c9378e6ce57a1a01ca8f";
        String logi = login(keys, challenge);
        System.out.println(logi);

        String userChainId = "ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5";

        JSONObject js = openFile(doc,userChainId,keys);
        System.out.println(js.toString(1));
        System.out.println("----------");
        System.out.println(js.get("payload").toString());
        System.out.println("----------");
        //          JSONObject js = new JSONObject();
//        byte[] array = new byte[0];
//        String fileContent = "";
//        try {
////            array = Files.readAllBytes(Paths.get("Greedy4.pdf"));
////            fileContent = Base64.getEncoder().encodeToString(array);
//            fileContent = Base64.getEncoder().encodeToString("sdaasaaaa".getBytes());
//        } catch (Exception e) {
//            e.printStackTrace();
//            return;
//        }
//
//
//        js.put("payload", fileContent);
//        js.put("name", "filenamed");
//        js.put("category", "OTHER");
//        js.put("keywords", "");
//
//
//        String userChainIdPubKey = "2pYnhELKZnC4Ykg8YwE9zKRTnzcN2dbkNzFQhn6qR7fcmkoSZ5";
//
//        store(js.get("name").toString(), js.get("payload").toString(), userChainId, userChainIdPubKey);

    }

    //non-static method cannot be referenced from a static context
    private static byte[] sign(byte[] file, UserKeyPair kp) throws NoSuchAlgorithmException {
        Signature sig = new Signature(decodeBase58(kp.getPublicSignKey()), hexStringToByteArray(kp.getPrivateSignKey()));
        //sig.detached_verify(file, hexStringToByteArray(kp.getPrivateSignKey()));
        return sig.detached(file);
    }

    private static String hashString(String toHash) {
        return Hash.sha3String(toHash);
    }

    private String encodeBase58(byte[] toEncode) throws NoSuchAlgorithmException {
        return Base58Check.encode(toEncode);
    }

    private static byte[] decodeBase58(String toDecode) throws NoSuchAlgorithmException {
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

        if ((passphrase != null) && !(passphrase.equals(""))) {
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
        UserKeyPair keys = new UserKeyPair(publicEncKey, privateEncKey, publicSignKey, privateSignKey, phrase);
        return keys;
    }

    private static String diceware() {
        RollDice rd = new RollDice();
        String phrase = rd.phrase();
        return phrase;
    }

    public static EncryptedFile encryptFileToPublicKey(String fileData, String dstPublicKey) throws GeneralSecurityException, UnsupportedEncodingException {

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

        String symKey = Base64.getEncoder().encodeToString(hexStringToByteArray(hashString(fileKey + salt).replaceFirst("0x", "")));

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

    public static String decryptDataWithSymmetricKey ( String messageWithNonce, String key) {

    byte[] keyUint8Array = Base64.getDecoder().decode(key);
    byte[] messageWithNonceAsUint8Array = Base64.getDecoder().decode(messageWithNonce);
    byte[] nonce = new byte[24];
    byte[] message = new byte[messageWithNonceAsUint8Array.length - nonce.length];

    // extracts the nonce
    for(int i=0; i<nonce.length; i++){
        nonce[i] = messageWithNonceAsUint8Array[i];
    }
    // extracts the message
    for(int i = nonce.length, p=0; i<messageWithNonceAsUint8Array.length; i++, p++){
        message[p] = messageWithNonceAsUint8Array[i];
    }

    byte[] decrypted = new TweetNaclFast.SecretBox(keyUint8Array).open(message, nonce);
        if (decrypted == null) {
            throw new Error("Decryption failed");
        }

        return new String(decrypted); //base64DecryptedMessage
    };

    public static String encrypt(String data, Box key) {

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

    public static String decrypt(String messageWithNonce, Box key) {
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

    public static EncryptedDataWithPublicKey encryptDataToPublicKeyWithKeyPair(String data, String dstPublicEncKey, UserKeyPair userAkKeyPairs) throws GeneralSecurityException {
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

    public static EncryptedDataWithPublicKey encryptDataToPublicKeyWithKeyPair(String data, String dstPublicEncKey) throws GeneralSecurityException {
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

    public static FileToUpload getFileUploadData(FileObj fileObj, String userChainId, String userChainIdPubKey) throws GeneralSecurityException, UnsupportedEncodingException {

        String fileContents = fileObj.getPayload();
        EncryptedFile encryptedFile = encryptFileToPublicKey(fileContents, userChainIdPubKey);
        String docOriginalHash = hashString(fileContents);
        String syncPassHash = hashString(encryptedFile.getCredentials().getSyncPass());
        String docChainId = hashString(docOriginalHash);

        FileToUpload upload = new FileToUpload();
        upload.setDocId(docChainId);
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

    public static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    static OkHttpClient client = new OkHttpClient().newBuilder().connectTimeout(100, TimeUnit.SECONDS)
            .writeTimeout(100, TimeUnit.SECONDS)
            .readTimeout(300, TimeUnit.SECONDS)
            .build();

    private void init(String token, String baseUrl) {
        this.token = token;
        this.baseUrl = baseUrl;
    }

    //gets the challange and pass it down to another function to do the actual login, then callbacks it here
    private static String login(UserKeyPair kp, String ch) {
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

    private static String loginWithChallenge(String challenge, UserKeyPair keyPair) {
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

    private static String getEndpointUrl(String action) {
        String url = baseUrl + "/" + action + "?noapi=1";
        if (!(token == null || token.trim() == "")) {
            url = baseUrl + "/" + action + "?api=1&token=" + token;
        }
        return url;
    }

    private static String getEndpointUrl(String action, String appendix) {
        String url = baseUrl + "/" + action + "noapi=1";
        if (!(token == null && token.trim() == "")) {
            url = baseUrl + "/" + action + "?api=1&token=" + token;
        }
        if (!(appendix == null && appendix.trim() == "")) {
            url = url + appendix;
        }
        return url;
    }

    private static String getRequest(String url) {

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

    public static String post(String url, JSONObject json) throws IOException {
        RequestBody body = RequestBody.create(json.toString(), JSON);
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .build();
        try (Response response = client.newCall(request).execute()) {
            return response.body().string();
        }
    }

    private static String uploadFile(FileToUpload file) throws IOException {
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

    private static JSONObject submitCredentials(String docChainId,String userChainId){
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
        encryption.put("pubKeyB",  browserKeyPair.getPublicEncKey());

        browserPubKeySubmit.put("encryption", encryption);

        System.out.println("submit pubkey payload " +  browserPubKeySubmit);

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

    private static String decryptDataWithPublicAndPrivateKey(String payload,String srcPublicEncKey, String secretKey) {
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

    private static JSONObject decryptWithKeyPair(String userId, String docChainId, UserKeyPair keyPair){
        System.out.println("User device requests decryption info from server "+ docChainId + "  " + userId);
        String getUrl = getEndpointUrl("exchangecredentials", "&userId=" + userId + "&docId=" + docChainId);
        System.out.println("decryptWithKeyPair get request " + getUrl);
        String serverEncryptionInfo = getRequest(getUrl);

        JSONObject serverEncrptInfo = new JSONObject(serverEncryptionInfo);
        JSONObject encrpt = new JSONObject(serverEncrptInfo.get("encryption").toString());

        System.out.println("Server responds to device with encryption info "+ serverEncrptInfo);

        if (encrpt == null || browserKeyPair.getPublicEncKey() == null) {
            throw new Error("Unable to retrieve intermediate public key B.");
        }
        String decryptedPassword = decryptDataWithPublicAndPrivateKey(encrpt.get("encryptedPassA").toString(), encrpt.get("pubKeyA").toString(), keyPair.getPrivateEncKey());
        System.out.println("User device decrypts the sym password " + decryptedPassword);
        String syncPassHash = hashString(decryptedPassword);
        EncryptedDataWithPublicKey reEncryptedPasswordInfo = null;
        try {
            reEncryptedPasswordInfo = encryptDataToPublicKeyWithKeyPair(decryptedPassword,browserKeyPair.getPublicEncKey(), keyPair);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        System.out.println("User device re-encrypts password for browser " + reEncryptedPasswordInfo);

        JSONObject devicePost = new JSONObject();
        devicePost.put("docId",docChainId );
        devicePost.put("userId","ak_" + keyPair.getPublicSignKey());

        JSONObject encryption = new JSONObject();
        encryption.put("syncPassHash", syncPassHash);
        encryption.put("encryptedPassB",reEncryptedPasswordInfo.getPayload());

        devicePost.put("encryption", encryption);

        System.out.println("devicePost "+ devicePost);
        String postUrl = getEndpointUrl("exchangecredentials");
        System.out.println("decryptWithKeyPair post "+ postUrl);

        String serverPostResponse = null;
        try {
            serverPostResponse = post(postUrl, devicePost);
        } catch (IOException e) {
            e.printStackTrace();
        }

        JSONObject serverResponse = new JSONObject(serverPostResponse);

        System.out.println("User device POST to server encryption info "+ devicePost);
        System.out.println("Server responds to user device POST "+ serverResponse.toString());
        return serverResponse;
    }

    private static JSONObject processEncryptedFileInfo(JSONObject encryptedFileInfo, String devicePublicKey, String browserPrivateKey) {
        JSONObject encryption = new JSONObject(encryptedFileInfo.get("encryption").toString());
        System.out.println("ei toz encryption" + encryption);
        System.out.println("ei toz parametar" + encryptedFileInfo);
        String decryptedSymPassword = decryptDataWithPublicAndPrivateKey(encryption.get("encryptedPassB").toString(), devicePublicKey, browserPrivateKey);
        System.out.println("Browser decrypts sym password " + decryptedSymPassword);

        String fullPassword = Base64.getEncoder().encodeToString(hexStringToByteArray(hashString(decryptedSymPassword + encryption.get("salt").toString()).replaceFirst("0x", "")));
        System.out.println("Browser composes full password " + fullPassword);

        String decryptedFile = decryptDataWithSymmetricKey(encryptedFileInfo.get("payload").toString(), fullPassword);
        System.out.println("Browser decrypts the file with the full password "+ decryptedFile);

        JSONObject resultFileInfo = encryptedFileInfo;
        resultFileInfo.put("payload",decryptedFile);
        resultFileInfo.put("encryption", "");
        return resultFileInfo;
    }

    private static JSONObject validateFile(String fileContents, String userId, String docId){
        String fileHash = hashString(fileContents);
        String validateUrl = getEndpointUrl("validate");

        JSONObject file = new JSONObject();
        file.put("userId", userId);
        file.put("docId", docId);

        JSONObject encryption = new JSONObject();
        encryption.put("decryptedDocHash",fileHash);

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

    private static JSONObject pollForFile(JSONObject credentialsResponse, String receiverPubKey){
        if (credentialsResponse.get("userId").toString() != null) {
            String pollUrl = getEndpointUrl("docencrypted", "&userId=" + credentialsResponse.get("userId").toString()+ "&docId=" + credentialsResponse.get("docId").toString());

            for (int i = 0; i < 50; i++) {
                String pollRes = getRequest(pollUrl);

                JSONObject pollResult = new JSONObject(pollRes);
                JSONObject encryption = new JSONObject(pollResult.get("encryption").toString());

                System.out.println("browser poll result "+ pollResult.toString());

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

    // End-functions
    public static String store(String name, String content, String userChainId, String userChainIdPubKey) {
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

    public static JSONObject openFile(String docChainId, String userChainId, UserKeyPair keyPair){
        JSONObject credentialsResponse = submitCredentials(docChainId,userChainId);
        JSONObject scanResult = decryptWithKeyPair(userChainId, docChainId, keyPair);
        if (scanResult.get("userId").toString() != null) {
            //polling server for pass to decrypt message
            return pollForFile(credentialsResponse, keyPair.getPublicEncKey());
        } else {
            throw new Error("Unable to decrypt file");
        }
    }
}
