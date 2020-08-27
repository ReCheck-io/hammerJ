package io.recheck.client.Crypto;

import com.google.gson.Gson;
import com.lambdaworks.crypto.SCrypt;
import io.recheck.client.POJO.*;
import io.recheck.client.RollDice;
import okhttp3.*;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.kocakosm.jblake2.Blake2s;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.logging.Logger;

import static java.util.Arrays.copyOfRange;


public class Utils {
    private static String token = "";
    private static final String defaultRequestId = "ReCheck";
    private static String network = "ae"; //ae or eth  
    private static UserKeyPair browserKeyPair = new UserKeyPair("", "", "", "", "");
    // TODO: Change the baseUrl to have instances
    private static String baseUrl = "https://beta.recheck.io";
    public static final Pattern VALID_EMAIL_ADDRESS_REGEX =
            Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);
    public static final Pattern VALID_AETHERNITY = Pattern.compile("^ak_[0-9a-zA-Z]{41,}$", Pattern.CASE_INSENSITIVE);
    public static final Pattern VALID_ETHEREUM = Pattern.compile("^0x[0-9a-fA-F]{40}$", Pattern.CASE_INSENSITIVE);
    public final Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);


    public static String getToken() {
        return token;
    }

    public static void setToken(String token) {
        Utils.token = token;
    }



    /**
     * Function to sign the bytes of a file using TweetNacl Signature class.
     *
     * @param file    file or message to encrypt
     * @param keyPair user's key pair
     * @return a byte array with the signature of the signature
     * @throws NoSuchAlgorithmException
     */
    protected byte[] sign(byte[] file, UserKeyPair keyPair) throws NoSuchAlgorithmException {
        TweetNaclFast.Signature sig = new TweetNaclFast.Signature(decodeBase58(keyPair.getPublicSignKey()), hexStringToByteArray(keyPair.getPrivateSignKey()));
        return sig.detached(file);
    }

    /**
     * @param toHash message or file in the form of a String to be hashed with sha3(keccak256)
     * @return sha3 hash with 0x
     */
    public String getHash(String toHash) {
        return Hash.sha3String(toHash);
    }

    /**
     * @param toHash message or file in the form of a String to be hashed with sha3(keccak256)
     * @return sha3 hash without 0x
     */
    public String keccak256(String toHash) {
        return Hash.sha3String(toHash).replaceFirst("0x", "");
    }

    /**
     * It will sign the contents of the object, without the payload, passed to the backend
     *
     * @param requestJSON
     * @return a hash of the post request's content
     */
    public String getRequestHashJSON(SortedMap requestJSON) {

        requestJSON.put("payload", "");
        requestJSON.put("requestBodyHashSignature", "NULL");

        Gson gson = new Gson();

        // Convert the ordered map into an ordered string.
        String requestString = gson.toJson(requestJSON);
        requestString = requestString.replace("\\u003d", "=");

        return getHash(requestString);
    }

    /**
     * It will sign the contents of the object, without the payload, passed to the backend
     *
     * @param requestJSON
     * @return a hash of the post request's content
     */
    public String getObjectIntoByte64(SortedMap requestJSON) {
        Gson gson = new Gson();

        // Convert the ordered map into an ordered string.
        String requestString = gson.toJson(requestJSON);
        requestString = requestString.replace("\\u003d", "=");

        byte[] requestStringBytes = requestString.getBytes();

        String result = Base64.getEncoder().encodeToString(requestStringBytes);

        return result;
    }

    /**
     * It will sign the contents of the url request, without the payload, passed to the backend
     *
     * @param url     the parameters passed for post/get request
     * @param keyPair user's key pair
     * @return hash of the contents then put into one of the parameters. This is because server check is made
     * once the request reach its destination.
     */

    public String getRequestHashURL(String url, UserKeyPair keyPair) {
        String hashedURL = getHash(url);
        String signedUrl = signMessage(hashedURL, keyPair);
        url = url.replace("NULL", signedUrl);

        return url;
    }



    /**
     * Gets a byte array and coverts it into String on the Base58 scheme.
     *
     * @param toEncode a byte array to be encoded
     * @return Base58 encoded String
     * @throws NoSuchAlgorithmException
     */
    private String encodeBase58(byte[] toEncode) throws NoSuchAlgorithmException {
        return Base58Check.encode(toEncode);
    }

    /**
     * Takes a Base58 encoded String and returns a byte array.
     *
     * @param toDecode A Base58 encoded string to be decoded
     * @return decoded information in the form of byte array
     * @throws NoSuchAlgorithmException This exception is thrown when a particular cryptographic algorithm is requested
     *                                  but is not available in the environment.
     */
    private byte[] decodeBase58(String toDecode) throws NoSuchAlgorithmException {
        toDecode = toDecode.replace("ak_", "");
        return Base58Check.decode(toDecode);
    }


    /**
     * session25519 is a public key cryptography library for the generation of Curve25519 encryption and ed25519 digital signature keys.
     * <p>
     * The encryption and signing keys are created with TweetNaCl.js, a port of TweetNaCl / NaCl.
     * The encryption keys are for the Public-key authenticated encryption box construction which implements
     * curve25519-xsalsa20-poly1305. The signing keys are for the ed25519 digital signature system.
     *
     * @param key2 - six random words concatenated into a String with a space delimiter
     * @param key1 - six random words concatenated into a String with a space delimiter
     * @return byte array that is going to be used for the creation of Sign and Encryption keys
     * @throws GeneralSecurityException The GeneralSecurityException class is a generic security exception class that
     *                                  provides type safety for all the security-related exception classes that extend from it.
     */
    public byte[] session25519(String key1, String key2) throws GeneralSecurityException {
        int logN = 131072;  // this number is 2^17  CPU/memory cost parameter (1 to 31)
        int r = 8;    // block size parameter
        int p = 1;   // Parallelization parameter.
        int dkLen = 64;   // length of derived key in Bytes

        // by definition, the second key is used as salt and need only be converted to byte[]
        byte[] key1Bytes = key1.getBytes();

        // takes the first six words and encodes them with Blake2s
        byte[] key2Bytes = key2.getBytes();
        Blake2s key2Blake = new Blake2s(32); // A 32 Byte hash of the password
        key2Blake.update(key2Bytes);
        byte[] blakeHash = key2Blake.digest();

        byte[] derivedBytes = SCrypt.scrypt(blakeHash, key1Bytes, logN, r, p, dkLen);

        return derivedBytes;

        // From the derivedBytes creating the seed for the following two key pairs
        // byte[] encryptKeySeed = copyOfRange(derivedBytes, 0, 32);
        // byte[] signKeySeed = copyOfRange(derivedBytes, 32, 64);
    }

    /**
     * @param passphrase - the secret 12 random words, which the user should be keeping secret and save in order to
     *                   recover their account in case something happens.
     *                   <p>
     *                   In case this parameter is null or empty, it means that there is a new account to be created. It
     *                   happens by using diceware method to choose the random 12 words.
     *                   <p>
     *                   It keyPair containing one address, public and private Sign keys,
     *                   public and private Encryption keys and the security phrase.
     * @return UserKeyPair object, containing the important information.
     * @throws GeneralSecurityException The GeneralSecurityException class is a generic security exception class that
     *                                  provides type safety for all the security-related exception classes that extend from it.
     */

    public UserKeyPair newKeyPair(String passphrase) throws GeneralSecurityException {

        if ((passphrase != null) && !(passphrase.equals(""))) {
            passphrase = passphrase.trim();
            String[] words = StringUtils.split(passphrase);
            if (words.length != 12) {
                System.err.println("Invalid passphrase. Your input is " + words.length + " words. It must be 12 words long.");
                System.exit(0);
            }
        } else {
            String[] fullphrase = StringUtils.split(diceware());
            for (int i = 0; i < 12; i++) {
                passphrase += fullphrase[0] + " ";
            }
        }


        //gets the 64 byte for the creation of the two key pairs
        // instead of k1 and k2 => phrase and getHash(phrase)
        byte[] derivedBytes = session25519(passphrase, getHash(passphrase));

        //the first 32 bytes are used for the encryption pair, the second - sing pair.
        byte[] encryptKeySeed = copyOfRange(derivedBytes, 0, 32);
        byte[] signKeySeed = copyOfRange(derivedBytes, 32, 64);

        // creating a TweetNacl Box object for the encrypt pair
        TweetNaclFast.Box.KeyPair keyPairSK = TweetNaclFast.Box.keyPair_fromSecretKey(encryptKeySeed);

        // Having the second key pair TweetNacl Signature
        TweetNaclFast.Signature.KeyPair keyPairS = TweetNaclFast.Signature.keyPair_fromSeed(signKeySeed);

        String publicEncKey = Base58Check.encode(keyPairSK.getPublicKey());
        String privateEncKey = bytesToHex(keyPairSK.getSecretKey());

        String publicSignKey = null;
        String privateSignKey = null;
        String address = null;

        switch (network) {
            case "ae":
                publicSignKey = "ak_" + Base58Check.encode(keyPairS.getPublicKey());
                privateSignKey = bytesToHex(keyPairS.getSecretKey());
                address = publicSignKey;
                break;

            case "eth":
                privateSignKey = "0x" + bytesToHex(keyPairSK.getSecretKey());
                Credentials credentials = Credentials.create(privateSignKey);

                publicSignKey = credentials.getEcKeyPair().getPublicKey().toString(16);
                address = credentials.getAddress();
                break;
        }

        // put all the keys in the User keyPair's object
        return new UserKeyPair(address, publicEncKey, privateEncKey, publicSignKey, privateSignKey, passphrase);
    }

    /**
     * This method is used to choose 12 random, easy to remember, words for a pass phrase. This phrase has to be saved by
     * the user on a save place, so that when something bad happens, they will be able to recover their account.
     *
     * @return String containing 12 words.
     */
    private String diceware() {
        RollDice rd = new RollDice();
        return rd.phrase();
    }

    /**
     * A function to return the blockchain currently used. It is to be used only in JUnit tests.
     *
     * @return a string with the value of either eth for Ethereum or ae for Aeternity blockchain
     */
    public String getNetwork() {
        return network;
    }

    /**
     * A function to set the blockchain currently used. It is to be used only in JUnit tests.
     *
     * @param net - setting the blockchain to be used
     */

    public void setNetwork(String net) {
        network = net;
    }


    /**
     * Creates a key and salt in order to create symmetric key. This Sym key is going to be used for the file encryption.
     * <p>
     * On the other hand the newly created key is encrypted with another, so that it can be sent along with the salt to
     * the receiver who has the means to decrypt the key, re-create the Sym key and decrypt the file.
     * <p>
     * As final step encapsulates the credentials of the file and its encrypted hash to pass them to the caller.
     *
     * @param fileData     The payload from the file in the form of a hash
     * @param dstPublicKey The public key of the receiver
     * @return an object with encapsulated file's credentials
     * @throws GeneralSecurityException     The GeneralSecurityException class is a generic security exception class that
     *                                      provides type safety for all the security-related exception classes that extend from it.
     * @throws UnsupportedEncodingException The Character Encoding is not supported.
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

        LOGGER.fine("fileKey " + fileKey);
        LOGGER.fine("salt " + salt);

        String symKey = Base64.getEncoder().encodeToString(hexStringToByteArray(keccak256(fileKey + salt)));

        LOGGER.fine(symKey);

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
     * Encrypts the String data with TweetNaclFast Box type.
     *
     * @param data the message to be encrypted
     * @param key  a Base64 encoded key (in the program we encode a sha3 hashed String)
     * @return String encrypted message then encoded in Base64
     * @throws UnsupportedEncodingException The Character Encoding is not supported.
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
     * Takes the Base64 encoded secret message, decodes it and then decrypts it.
     *
     * @param messageWithNonce a Base64 encoded message
     * @param key              a Base64 encoded key
     * @return decrypted String message
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
     * @param data String data payload
     * @param key  Shared key - Box TweetNacl - that will be used for encryption of the data
     * @return base64 String private key encrypted message
     */
    public String encryptData(String data, TweetNaclFast.Box key) {

        byte[] theNonce = TweetNaclFast.makeSecretBoxNonce();
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

    /**
     * Takes as input secret or shared key and an encrypted data as a hash of type String that needs to be decrypted.
     * Using asymmetric public key encryption.
     *
     * @param messageWithNonce a Base64 encoded message with the nonce
     * @param key              a TweetNacl Box object
     * @return decrypted String message
     */
    public String decryptData(String messageWithNonce, TweetNaclFast.Box key) {
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
            LOGGER.severe("The decryption failed");
            System.exit(0);
        }
        String decryptedBase64Message = new String(decrypted);
        return decryptedBase64Message;
    }

    /**
     * This function takes someone's public key and user's private to encrypt the data with TweetNacl Box function.
     *
     * @param data            a String message to be encrypted
     * @param dstPublicEncKey the public key of the receiver
     * @param userAkKeyPairs  the key pair of the sender
     * @return an object encapsulating the payload of the encrypted file along with the private and public key needed
     * for the encryption
     * @throws GeneralSecurityException The GeneralSecurityException class is a generic security exception class that
     *                                  provides type safety for all the security-related exception classes that extend from it.
     */
    public EncryptedDataWithPublicKey encryptDataToPublicKeyWithKeyPair(String data, String dstPublicEncKey, UserKeyPair userAkKeyPairs) throws GeneralSecurityException {
        if (userAkKeyPairs == null) {
            //passing a null variable to escape overloading the whole parameter
            String generate = null;
            userAkKeyPairs = newKeyPair(generate);
        }
        byte[] destPublicEncKeyArray = decodeBase58(dstPublicEncKey);
        byte[] mySecretEncKeyArray = hexStringToByteArray(userAkKeyPairs.getPrivateEncKey());

        // create BOX object to make the .before method
        TweetNaclFast.Box sharedKeyBox = new TweetNaclFast.Box(destPublicEncKeyArray, mySecretEncKeyArray);
        String encryptedData = encryptData(data, sharedKeyBox);

        //Putting the data into a object data struct (JS like)
        EncryptedDataWithPublicKey result = new EncryptedDataWithPublicKey();
        result.setPayload(encryptedData);
        result.setDstPublicEncKey(dstPublicEncKey);
        result.setSrcPublicEncKey(userAkKeyPairs.getPublicEncKey());

        return result;
    }

    /**
     * This function takes someone's public key and user's private to encrypt the data with TweetNacl Box function.
     * <p>
     * Overrides the previous function, when there is no specified private key.
     *
     * @param data            a String message to be encrypted
     * @param dstPublicEncKey The receiver's public key
     * @return an object encapsulating the payload of the encrypted file along with the private and public key needed
     * for the encryption
     * @throws GeneralSecurityException The GeneralSecurityException class is a generic security exception class that
     *                                  provides type safety for all the security-related exception classes that extend from it.
     */
    public EncryptedDataWithPublicKey encryptDataToPublicKeyWithKeyPair(String data, String dstPublicEncKey) throws GeneralSecurityException {
        String generate = null;
        UserKeyPair srcAkPair = newKeyPair(generate);

        byte[] destPublicEncKeyArray = decodeBase58(dstPublicEncKey);
        byte[] mySecretEncKeyArray = hexStringToByteArray(srcAkPair.getPrivateEncKey());

        // create BOX object to make the .before method
        TweetNaclFast.Box sharedKeyBox = new TweetNaclFast.Box(destPublicEncKeyArray, mySecretEncKeyArray);
        String encryptedData = encryptData(data, sharedKeyBox);

        //Putting the data into a object data struct (JS like)
        EncryptedDataWithPublicKey result = new EncryptedDataWithPublicKey();
        result.setPayload(encryptedData);
        result.setDstPublicEncKey(dstPublicEncKey);
        result.setSrcPublicEncKey(srcAkPair.getPublicEncKey());

        return result;
    }

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    /**
     * function to convert byte array to hex String
     *
     * @param bytes bytes array to be converted
     * @return String with hex Chars
     */
    public String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars).toLowerCase();
    }

    /**
     * function to convert a hex String into byte[]
     *
     * @param s - hex String
     * @return the converted String into byte array
     */
    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }


    /**
     * This function takes as input the file, user's id and their pubKey. Prepares the data and needed to indentify the file
     * upon uploading into the system.
     *
     * @param fileObj a fileObj containing info about the object and it is about to be uploaded
     * @param keyPair the keyPair of the user
     * @return an object encapsulating the data needed to be stored per single file
     * @throws GeneralSecurityException     The GeneralSecurityException class is a generic security exception class that
     *                                      provides type safety for all the security-related exception classes that extend from it.
     * @throws UnsupportedEncodingException The Character Encoding is not supported.
     */
    public FileToUpload getFileUploadData(FileObj fileObj, UserKeyPair keyPair) throws GeneralSecurityException, UnsupportedEncodingException {

        String fileContents = fileObj.getPayload();
        EncryptedFile encryptedFile = encryptFileToPublicKey(fileContents, keyPair.getPublicEncKey());

        String dataOriginalHash = getHash(fileContents);
        String syncPassHash = getHash(encryptedFile.getCredentials().getSyncPass());
        String dataChainId = getHash(dataOriginalHash);
        String requestType = "upload";

        String trailHash = getHash(dataChainId + keyPair.getPublicSignKey() + requestType + keyPair.getPublicSignKey());


        FileToUpload upload = new FileToUpload();
        upload.setUserId(keyPair.getPublicSignKey());
        upload.setDataId(dataChainId);
        upload.setRequestId(defaultRequestId);
        upload.setRequestType(requestType);
        upload.setRequestBodyHashSignature("NULL");
        upload.setTrailHash(trailHash);
        upload.setTrailHashSignatureHash(getHash(trailHash));
        upload.setDataName(fileObj.getName());
        upload.setDataExtension(fileObj.getDataExtention());
        //TODO: Change once these are realised
        if (fileObj.getCategory() == null) {
            upload.setCategory("OTHER");
        }
        if (fileObj.getKeywords() == null) {
            upload.setKeywords("Daka");
        }
        upload.setPayload(encryptedFile.getPayload());

        Encryption encrpt = new Encryption();

        encrpt.setDataHash(dataOriginalHash);
        encrpt.setSalt(encryptedFile.getCredentials().getSalt());
        encrpt.setPassHash(syncPassHash);
        encrpt.setEncryptedPassA(encryptedFile.getCredentials().getEncryptedPass());
        encrpt.setPubKeyA(encryptedFile.getCredentials().getEncryptedPubKey());

        upload.setEncrypt(encrpt);

        return upload;

    }

    public final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    /**
     * OKHttpClient settings for get and post requests.
     */
    static OkHttpClient client = new OkHttpClient().newBuilder().connectTimeout(100, TimeUnit.SECONDS)
            .writeTimeout(100, TimeUnit.SECONDS)
            .readTimeout(300, TimeUnit.SECONDS)
            .build();

    /**
     * Creates a JSON object to put into post request in order for the user to log into the system.
     *
     * @param challenge the identification given by the server, so that the user can access the web GUI
     * @param keyPair   user's keypair
     * @return the token response, either success or fail
     */
    public String loginWithChallenge(String challenge, UserKeyPair keyPair) {
        try {
            String sig58 = signMessage(challenge, keyPair);
            JSONObject payload = new JSONObject();

            payload.put("action", "login");
            payload.put("pubKey", keyPair.getPublicSignKey());
            payload.put("pubEncKey", keyPair.getPublicEncKey());
            payload.put("firebase", "notoken");
            payload.put("challenge", challenge);
            payload.put("challengeSignature", sig58);
            payload.put("rtnToken", "notoken");

            String loginURL = getEndpointUrl("login/mobile");

            String loginPostResult = post(loginURL, payload);

            JSONObject data = new JSONObject(loginPostResult);

            JSONObject result = new JSONObject(data.get("data").toString());

            String tokenRes = result.get("rtnToken").toString();

            setToken(tokenRes);
            return tokenRes;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "Err";

    }


    /**
     * Helper function to redirect to the correct http address
     *
     * @param action - type of action - mobilelogin etc.
     * @return String with correct http address
     */

    public String getEndpointUrl(String action) {
        String url = baseUrl + "/" + action + "?api=1";
        if (!(token == null || token.trim() == "")) {
            url = baseUrl + "/" + action + "?api=1&token=" + token;
        }
        return url;
    }

    /**
     * Overloading of the function with the addition of an appendix.
     *
     * @param action   - type of action - mobilelogin etc.
     * @param appendix - the specific parameters for the corresponding action
     * @return String with correct http address
     */

    public String getEndpointUrl(String action, String appendix) {
        String url = baseUrl + "/" + action + "?api=1";
        if (!(token == null && token.trim() == "")) {
            url = baseUrl + "/" + action + "?api=1&token=" + token;
        }
        if (!(appendix == null && appendix.trim() == "")) {
            LOGGER.fine("appendix" + appendix);
            url = url + appendix;
        }
        return url;
    }

    /**
     * Method to send get request to the server
     *
     * @param url the url to the server API
     * @return JSON object in the form of a String
     */
    public String getRequest(String url) {

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

    /**
     * Method to send post request to the given url and json
     *
     * @param url  the server url to which the request to be sent
     * @param json the json containing the object to be sent
     * @return String with the result of the request
     * @throws IOException Signals that an I/O exception of some sort has occurred. This class is the general class of
     *                     exceptions produced by failed or interrupted I/O operations.
     */
    public String post(String url, JSONObject json) throws IOException {
        RequestBody body = RequestBody.create(json.toString(), JSON);
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .build();
        try (Response response = client.newCall(request).execute()) {
            return response.body().string();
        }
    }

    /**
     * Method that gets a file and encapsulates it into JSON file in order to post the details on the blockchain.
     *
     * @param file the object containing the info to put into json and post send
     * @return the server response after sending the json
     * @throws IOException Signals that an I/O exception of some sort has occurred. This class is the general class of
     *                     exceptions produced by failed or interrupted I/O operations.
     */

    public String uploadFile(FileToUpload file) throws IOException {
        SortedMap<String, Object> js = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        js.put("userId", file.getUserId());
        js.put("dataId", file.getDataId());
        js.put("requestId", file.getRequestId());
        js.put("requestType", file.getRequestType());
        js.put("requestBodyHashSignature", "NULL");
        js.put("trailHash", file.getTrailHash());
        js.put("trailHashSignatureHash", file.getTrailHashSignatureHash());
        js.put("dataName", file.getDataName());
        js.put("dataExtension", file.getDataExtension());
        js.put("category", file.getCategory());
        js.put("keywords", file.getKeywords());
        js.put("payload", "");

        SortedMap<String, Object> encryption = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        encryption.put("dataOriginalHash", file.getEncrypt().getDataHash());
        encryption.put("salt", file.getEncrypt().getSalt());
        encryption.put("passHash", file.getEncrypt().getPassHash());
        encryption.put("encryptedPassA", file.getEncrypt().getEncryptedPassA());
        encryption.put("pubKeyA", file.getEncrypt().getPubKeyA());

        js.put("encryption", encryption);

        String requestBodySig = getRequestHashJSON(js);

        js.put("payload", file.getPayload());

        js.put("requestBodyHashSignature", requestBodySig);

        JSONObject upload = new JSONObject(js);
        String submitUrl = getEndpointUrl("data/create");
        LOGGER.info("Store post" + submitUrl);
        String response = post(submitUrl, upload);

        JSONObject uploadResult = new JSONObject(response);

        LOGGER.severe("Store result" + uploadResult.get("data").toString());
        return uploadResult.get("data").toString();
    }

    /**
     * This method prepares the browser with key pair if it does not already have in order
     * for secure communication to take place. For more info take a look at ReCheck protocol for secure communication.
     *
     * @param dataChainId the hash of the file or message that is written in the blockchain
     * @param userChainId user's chain id (public key)
     * @return the server's response, which should be the browser key pair
     */

    public JSONObject prepare(String dataChainId, String userChainId) {
        if (browserKeyPair.getPublicEncKey() == null) {
            try {
                browserKeyPair = newKeyPair("");
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
        }
        LOGGER.fine("Browser has key: " + browserKeyPair.getPublicSignKey());
        JSONObject browserPubKeySubmit = new JSONObject();

        browserPubKeySubmit.put("dataId", dataChainId);
        browserPubKeySubmit.put("userId", userChainId);

        JSONObject encryption = new JSONObject();
        encryption.put("pubKeyB", browserKeyPair.getPublicEncKey());

        browserPubKeySubmit.put("encryption", encryption);

        LOGGER.fine("submit pubkey payload " + browserPubKeySubmit);

        String browserPubKeySubmitUrl = getEndpointUrl("credentials/create/pubkeyb");
        LOGGER.fine("browser poll post submit pubKeyB " + browserPubKeySubmitUrl);

        String browserPubKeySubmitRes = null;
        try {
            browserPubKeySubmitRes = post(browserPubKeySubmitUrl, browserPubKeySubmit);

            JSONObject js = new JSONObject(browserPubKeySubmitRes);
            JSONObject credentials = new JSONObject(js.get("data").toString());

            return credentials;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }

    /**
     * Takes encrypted data - payload - and then with the sender's public and the receiver's secret key
     * decrypts the data.
     *
     * @param payload         encrypted data
     * @param srcPublicEncKey sender's public key
     * @param secretKey       receiver's secret key
     * @return decrypted data
     */

    public String decryptDataWithPublicAndPrivateKey(String payload, String srcPublicEncKey, String secretKey) {
        byte[] srcPublicEncKeyArray = null;
        try {
            srcPublicEncKeyArray = decodeBase58(srcPublicEncKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] secretKeyArray = hexStringToByteArray(secretKey);
        TweetNaclFast.Box decryptedBox = new TweetNaclFast.Box(srcPublicEncKeyArray, secretKeyArray);
        return decryptData(payload, decryptedBox);//decrypted
    }


    /**
     * Processing the encryption to decryption process, by creating the full password and decrypting the data
     *
     * @param encryptedFileInfo the encrypted file object
     * @param devicePublicKey   mobile device, or the user's, public key
     * @param browserPrivateKey the browser's private key
     * @return JSON obj result with the decrypted data.
     */

    private JSONObject processEncryptedFileInfo(JSONObject encryptedFileInfo, String devicePublicKey, String browserPrivateKey) {
        JSONObject encryption = new JSONObject(encryptedFileInfo.get("encryption").toString());

        String decryptedSymPassword = decryptDataWithPublicAndPrivateKey(encryption.get("encryptedPassB").toString(), devicePublicKey, browserPrivateKey);
        LOGGER.fine("Browser decrypts sym password " + decryptedSymPassword);

        String fullPassword = Base64.getEncoder().encodeToString(hexStringToByteArray(keccak256(decryptedSymPassword + encryption.get("salt").toString())));
        LOGGER.fine("Browser composes full password " + fullPassword);

        String decryptedFile = decryptDataWithSymmetricKey(encryptedFileInfo.get("payload").toString(), fullPassword);
        LOGGER.fine("Browser decrypts the file with the full password " + decryptedFile);

        JSONObject resultFileInfo = encryptedFileInfo;
        resultFileInfo.put("payload", decryptedFile);
        resultFileInfo.put("encryption", "");
        return resultFileInfo;
    }
    /**
     * Verification of the file decryption, before returning it to the user who has selected to open/download it
     *
     * @param fileContents hash of the file
     * @param userId       user's chain ID
     * @param dataId       file's chain ID
     * @return the result taken from the server, after sending the data for double check
     */

    private JSONObject validate(String fileContents, String userId, String dataId) {
        String fileHash = getHash(fileContents);

        String requestType = "verify";
        String trailHash = getHash(dataId + userId + requestType + userId);


        SortedMap<String, Object> file = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        file.put("userId", userId);
        file.put("dataId", dataId);
        file.put("requestId", defaultRequestId);
        file.put("requestType", requestType);
        file.put("requestBodyHashSignature", "NULL");
        file.put("trailHash", trailHash);
        file.put("trailHashSignatureHash", getHash(trailHash));

        SortedMap<String, Object> encryption = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        encryption.put("decryptedDataHash", fileHash);

        file.put("encryption", encryption);
        String requestBodSig = getRequestHashJSON(file);
        file.put("requestBodyHashSignature", requestBodSig);


        JSONObject upload = new JSONObject(file);

        String validateUrl = getEndpointUrl("credentials/validate");

        String result = null;
        try {
            result = post(validateUrl, upload);
        } catch (IOException e) {
            e.printStackTrace();
        }


        //TODO: write a good condition if result is NULL
        JSONObject res = new JSONObject(result);
        LOGGER.fine(res.toString());
        if (res.toString() == null) {
            LOGGER.severe("Unable to verify file.");
        } else {
            LOGGER.fine("File contents validated.");
        }

        return res;
    }
    /**
     * Searches for file based on the credential, data id and user id, given.
     *
     * @param credentialsResponse The response of the credentials from the user's id and the file/selection they
     *                            want to open
     * @param receiverPubKey      receiver's public key
     * @return decrypted file or a selection of files
     */
    public JSONObject poll(JSONObject credentialsResponse, String receiverPubKey) {
        if (credentialsResponse.get("userId").toString() != null) {
            String pollUrl = getEndpointUrl("data/info", "&userId=" + credentialsResponse.get("userId").toString() + "&dataId=" + credentialsResponse.get("dataId").toString());

            for (int i = 0; i < 50; i++) {
                String pollRes = getRequest(pollUrl);

                JSONObject pollResult = new JSONObject(pollRes);
                JSONObject dataPollRes = new JSONObject(pollResult.get("data").toString());
                JSONObject encryption = new JSONObject(dataPollRes.get("encryption").toString());

                LOGGER.fine("browser poll result " + pollResult.toString());

                if (encryption.toString() != null) {
                    LOGGER.fine("Server responds to polling with " + pollResult.toString());
                    JSONObject decryptedFile = processEncryptedFileInfo(dataPollRes, receiverPubKey, browserKeyPair.getPrivateEncKey());

                    JSONObject validationResult = validate(decryptedFile.get("payload").toString(), decryptedFile.get("userId").toString(), decryptedFile.get("dataId").toString());
                    LOGGER.fine("validation object " + validationResult.toString());
                    // TODO: Better check ! what happens
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

    /**
     * Gets the number of file(s) that the user wants to open.
     *
     * @param selectionHash a hash of the selected files
     * @return the server response with the corresponding files
     */

    public String getSelected(String selectionHash) {
        String getUrl = getEndpointUrl("selection/info", "&selectionHash=" + selectionHash);
        LOGGER.fine("getSelectedFiles get request " + getUrl);
        String selectionResponse = getRequest(getUrl);
        LOGGER.fine("selection obj: " + selectionResponse);
        JSONObject selectionRes = new JSONObject(selectionResponse);

        return selectionRes.toString();
    }

    /**
     * Validation of an email
     *
     * @param emailStr - input email
     * @return whether the email is valid or not.
     */

    public static boolean validateEmail(String emailStr) {
        Matcher matcher = VALID_EMAIL_ADDRESS_REGEX.matcher(emailStr);
        return matcher.find();
    }

    /**
     * Validation of a blockchain address on AEthernity
     *
     * @param aeAddress - input address
     * @return whether the address is AE valid or not
     */

    public static boolean validateAEAddress(String aeAddress) {
        Matcher matcher = VALID_AETHERNITY.matcher(aeAddress);
        return matcher.find();
    }

    /**
     * Validation of a blockchain address on Ethereum
     *
     * @param ethAddress - input address
     * @return whether the address is eth valid or not
     */

    public static boolean validateEthAddress(String ethAddress) {
        Matcher matcher = VALID_ETHEREUM.matcher(ethAddress);
        return matcher.find();
    }


    public String[] recipientCheck(String recipientId) {

        String recipientType;
        String requestType = "share";

        if (validateEmail(recipientId)) {
            recipientType = "recipientEmail";
            requestType = "email";
        } else if (validateAEAddress(recipientId)) {
            recipientType = "recipientId";
            requestType = "share";
        } else if (validateEthAddress(recipientId)) {
            recipientType = "recipientId";
        } else {
            recipientType = "";
            try {
                throw new Exception("Address not valid");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        String[] result = new String[2];
        result[0] = recipientType;
        result[1] = requestType;

        return result;
    }

    /**
     * This method asks for the blockchain ID of the file and the blockchain ID (the address) of
     * a participant in the actions and returns the transactions made with the file.
     *
     * @param dataChainId - the blockchain id of the file
     * @param userId      - the blockchain address of user that is a participant in the transactions
     * @return - info about the transactions made with the file
     */

    public JSONObject checkHash(String dataChainId, String userId) {
        if (userId.contains("ak_")) {
            userId = userId.substring(3);
        }
        String query = "&userId=" + userId + "&dataId=" + dataChainId;

        String getUrl = getEndpointUrl("tx/info", query);
        LOGGER.severe("query URL " + getUrl);

        String serverResponse = getRequest(getUrl);
        JSONObject serverRes = new JSONObject(serverResponse);

        LOGGER.severe("Server responds to checkHash GET " + serverRes.get("data"));

        return serverRes;
    }


    /**
     * Function to sign a message, depending on the network eth/ae
     *
     * @param message message/file to sign
     * @param keyPair user's key pair to get the private key for signing
     * @return hash of the signature
     */

    public String signMessage(String message, UserKeyPair keyPair) {
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
                org.web3j.crypto.Credentials cs = Credentials.create(keyPair.getPrivateEncKey());
                Sign.SignatureData signature = Sign.signMessage(message.getBytes(), cs.getEcKeyPair(), true);

                String v = bytesToHex(signature.getV());
                String r = Numeric.toHexString(signature.getR());
                String s = Numeric.toHexString(signature.getS()).replaceFirst("0x", "");

                String sig = r + s + v;
                return sig;
        }
        return "";
    }



}
