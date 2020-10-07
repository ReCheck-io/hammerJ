package io.recheck.client;

import io.recheck.client.crypto.E2EEncryption;
import io.recheck.client.exceptions.*;
import io.recheck.client.model.*;
import org.json.JSONObject;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.logging.Logger;

import static java.util.Arrays.copyOfRange;


public class HammerJ {

    private static final String defaultRequestId = "ReCheck";
    // it will change to eth
    private static String baseUrl = "https://beta.recheck.io";
    private E2EEncryption e2EEncryption = new E2EEncryption();

    private static final String BOX_NONCE = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
    public final Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    /**
     * Initializing of the API token, baseURL (beta/my.recheck) and the network (currently ae or eth)
     *
     * @param token
     * @param baseUrl
     * @param network
     */
    public void init(String token, String baseUrl, String network) {
        E2EEncryption.setToken(token);
        this.baseUrl = baseUrl;
        e2EEncryption.setNetwork(network);
    }

    /**
     * This function checks if the user is having a challenge or not and then redirects to loginWithChallenge function.
     * If there is, then the user is also logged in the browser GUI. Otherwise, the user just
     * have access to the backend's APIs.
     * <p>
     * TODO check if wrong challenge is going to give me access
     *
     * @param userKeyPair - user's key Pair
     * @param ch          - challenge, what would be represented as QR in the website
     * @return the result of LoginWithChallenge
     * @throws ServerException
     * @throws IOException
     */

    public String login(UserKeyPair userKeyPair, String ch) throws ServerException, IOException {
        String getChallengeUrl = e2EEncryption.getEndpointUrl("login/challenge");
        String challengeResponse = e2EEncryption.getRequest(getChallengeUrl);
        JSONObject js = null;
        if (challengeResponse != null) {
            js = new JSONObject(challengeResponse);
        }

        JSONObject data = new JSONObject(js.get("data").toString());
        String challenge = data.get("challenge").toString();

        ch = ch.trim();

        if (ch.length() > 31) {
            challenge = ch;
        }

        LOGGER.severe("challenge response " + challengeResponse);

        return e2EEncryption.loginWithChallenge(challenge, userKeyPair);
    }

    /**
     * @param secretPhrase the secret phrase which contains the info for the user's key pairs
     * @return User key pairs
     * @throws GeneralSecurityException
     * @throws InvalidPhraseException
     */

    public UserKeyPair generateNewKeyPair(String secretPhrase) throws GeneralSecurityException, InvalidPhraseException {
        UserKeyPair keyPair = e2EEncryption.newKeyPair(secretPhrase);

        return keyPair;
    }

    /**
     * Decrypts with user's key pair. It is for the GUI to be asking keys for permission out of the mobile app.
     *
     * @param userId      user's chain ID
     * @param dataChainId file's chain ID
     * @param keyPair     user's key pair
     * @return response from the server whether the decryption has been successful or not
     * @throws EncodeDecodeException
     * @throws ServerException
     * @throws KeyExchangeException
     * @throws IOException
     */

    public JSONObject reEncrypt(String userId, String dataChainId, UserKeyPair keyPair) throws EncodeDecodeException, ServerException, KeyExchangeException, IOException {
//        String trailExtraArgs = null;
        LOGGER.fine("User device requests decryption info from server " + dataChainId + "  " + userId);
        String requestType = "download";
        String trailHash = e2EEncryption.getHash(dataChainId + userId + requestType + userId);
        String trailHashSignatureHash = e2EEncryption.getHash(e2EEncryption.signMessage(trailHash, keyPair));

        String query = "&userId=" + userId + "&dataId=" + dataChainId + "&requestId=" + defaultRequestId + "&requestType=" + requestType + "&requestBodyHashSignature=NULL&trailHash=" + trailHash + "&trailHashSignatureHash=" + trailHashSignatureHash;
        String getUrl = e2EEncryption.getEndpointUrl("credentials/info", query);

        //hashes the request, and puts it as a value inside the url
        getUrl = e2EEncryption.getRequestHashURL(getUrl, keyPair);
        LOGGER.fine("decryptWithKeyPair get request " + getUrl);
        String serverEncryptionInfo = e2EEncryption.getRequest(getUrl);

        JSONObject serverEncrptInfo = new JSONObject(serverEncryptionInfo);
        JSONObject data = new JSONObject(serverEncrptInfo.get("data").toString());
        JSONObject encrpt = new JSONObject(data.get("encryption").toString());

        LOGGER.fine("Server responds to device with encryption info " + serverEncrptInfo);

        if (encrpt == null || encrpt.get("pubKeyB").toString() == null) {
            throw new KeyExchangeException("Unable to retrieve intermediate public key B.");
        }
        String decryptedPassword = e2EEncryption.decryptDataWithPublicAndPrivateKey(encrpt.get("encryptedPassA").toString(), encrpt.get("pubKeyA").toString(), keyPair.getPrivateEncKey());
        decryptedPassword = decryptedPassword.replaceAll("\"", "");
        LOGGER.fine("User device decrypts the sym password " + decryptedPassword);
        String syncPassHash = e2EEncryption.getHash(decryptedPassword);
        EncryptedDataWithPublicKey reEncryptedPasswordInfo = null;
        try {
            reEncryptedPasswordInfo = e2EEncryption.encryptDataToPublicKeyWithKeyPair(decryptedPassword, encrpt.get("pubKeyB").toString(), keyPair);
        } catch (GeneralSecurityException | InvalidPhraseException e) {
            e.printStackTrace();
        }
        LOGGER.fine("User device re-encrypts password for browser " + reEncryptedPasswordInfo);

        JSONObject devicePost = new JSONObject();
        devicePost.put("dataId", dataChainId);
        devicePost.put("userId", keyPair.getAddress());

        JSONObject encryption = new JSONObject();
        encryption.put("syncPassHash", syncPassHash);
        encryption.put("encryptedPassB", reEncryptedPasswordInfo.getPayload());

        devicePost.put("encryption", encryption);

        LOGGER.fine("devicePost " + devicePost);
        String postUrl = e2EEncryption.getEndpointUrl("credentials/create/passb");
        LOGGER.fine("decryptWithKeyPair post " + postUrl);

        String serverPostResponse = null;

        serverPostResponse = e2EEncryption.post(postUrl, devicePost);

        JSONObject dataRes = new JSONObject(serverPostResponse);
        JSONObject serverResponse = new JSONObject(dataRes.get("data").toString());
        LOGGER.info("User device POST to server encryption info " + devicePost.toString(1));
        LOGGER.fine("Server responds to user device POST " + serverResponse.toString());
        return serverResponse;
    }


    /**
     * Shares the file either with other accounts from the network, that the user already have in contacts, or
     * by providing an email. With the email-share it also returns a link that sends a secret code to the email.
     * Only with the possession of this code can the contents of the share be decrypted.
     *
     * @param dataId      file's chain ID
     * @param recipientId recipient(s) chain ID
     * @param senderKeys  user/sender's key pair
     * @return a JSON obj containing the shared file
     */

    public JSONObject shareData(String dataId, String recipientId, UserKeyPair senderKeys) throws ServerException, EncodeDecodeException, GeneralSecurityException, InvalidPhraseException, IOException, ValidationException {
        boolean isEmailShare;
        isEmailShare = recipientId.contains("@");
        String[] recipientQuerySpecific = e2EEncryption.recipientCheck(recipientId);

        String recipientType = recipientQuerySpecific[0];
        String requestType = recipientQuerySpecific[1];

        //providing that the right API is called
        String getUrl = e2EEncryption.getEndpointUrl("share/credentials", "&dataId=" + dataId + "&" + recipientType + "=" + recipientId);
        LOGGER.fine("credentials/share get request " + getUrl);
        String getShareResponse = e2EEncryption.getRequest(getUrl);
        // Share response is going to give back data either for email or for an identity share
        LOGGER.fine("Share res " + getShareResponse);

        JSONObject shareResData = new JSONObject(getShareResponse);
        JSONObject shareRes = new JSONObject(shareResData.get("data").toString());

        // if the server is OK and gave back the correct data
        if (shareRes.get("dataId").toString().equals(dataId)) {
            //the encryption sent contains pub key of the receiver, if is to be to an identity
            JSONObject encryption = new JSONObject(shareRes.get("encryption").toString());

            //can go into a method
            String encryptedPassA = encryption.get("encryptedPassA").toString();
            String pubKeyA = encryption.get("pubKeyA").toString();
            String decryptedPassword = e2EEncryption.decryptDataWithPublicAndPrivateKey(encryptedPassA, pubKeyA, senderKeys.getPrivateEncKey());
            String syncPassHash = e2EEncryption.getHash(decryptedPassword);

            String recipientEncrKey = "";
            UserKeyPair recipientEmailLinkKeyPair = null;

            if (isEmailShare) {

                recipientEmailLinkKeyPair = e2EEncryption.newKeyPair(null);
                recipientEncrKey = recipientEmailLinkKeyPair.getPublicEncKey();

            } else {
                recipientEncrKey = encryption.get("recipientEncrKey").toString();
            }

            EncryptedDataWithPublicKey reEncryptedPasswordInfo = null;

            reEncryptedPasswordInfo = e2EEncryption.encryptDataToPublicKeyWithKeyPair(decryptedPassword, recipientEncrKey, senderKeys);

            String senderId = senderKeys.getAddress();
            String trailHash = e2EEncryption.getHash(dataId + senderId + requestType + recipientId);
            String trailHashSignatureHash = e2EEncryption.getHash(e2EEncryption.signMessage(trailHash, senderKeys));

            // can go into a method
            SortedMap<String, Object> createShare = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            createShare.put("userId", senderId);
            createShare.put("dataId", dataId);
            createShare.put("requestId", defaultRequestId);
            createShare.put("requestType", requestType);
            createShare.put("requestBodyHashSignature", "NULL");
            createShare.put("trailHash", trailHash);
            createShare.put("trailHashSignatureHash", trailHashSignatureHash);
            //TODO: instead of recipientId as key i will have recipientType 
            createShare.put(recipientType, recipientId);
            createShare.put("payload", "");

            SortedMap<String, Object> encrpt = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            encrpt.put("senderEncrKey", senderKeys.getPublicEncKey());
            encrpt.put("syncPassHash", syncPassHash);
            encrpt.put("encryptedPassA", reEncryptedPasswordInfo.getPayload());

            createShare.put("encryption", encrpt);

            String requestBodyHash = e2EEncryption.signMessage(e2EEncryption.getRequestHashJSON(createShare), senderKeys);

            createShare.put("requestBodyHashSignature", requestBodyHash);

            JSONObject jsCreateShare = new JSONObject(createShare);
            String postUrl = e2EEncryption.getEndpointUrl("share/create");

            String serverPostResponse = e2EEncryption.post(postUrl, jsCreateShare);

            //TODO: serverPostResponce and result could be null
            JSONObject postResponse = new JSONObject(serverPostResponse);
            LOGGER.info("Share POST to server encryption info " + jsCreateShare.toString(1));
            LOGGER.fine("Server responds to user device POST " + postResponse.toString());
            JSONObject serverResult = new JSONObject(postResponse.toString());
            try {
                if (!serverResult.get("data").toString().startsWith("{")) {
                    String[] message = serverResult.get("data").toString().split(",");
                    for (int i = 0; i < message.length; i++) {
                        //This message should stay
                        LOGGER.info(message[i]);
                    }
                    throw new Exception("Already sent");

                } else {

                    JSONObject result = new JSONObject(serverResult.get("data").toString());

                    //generating email keys and shareable link
                    if (isEmailShare) {
                        String shareUrl = generateEmailShareUrl(result, senderKeys, recipientEmailLinkKeyPair);
                        result.put("shareUrl", shareUrl);
                    }

                    return result;
                }

            } catch (Exception e) {
                e.getMessage();
            }

        } else {
            try {
                if (!shareRes.get("dataId").toString().equals(dataId)) {
                    throw new Exception("The data is different or missing");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return new JSONObject("{\"message\":{\"EN\":\"The sending has been interuppted.\"}}");
    }

    public JSONObject shareDataWithExternalID(String externalID, String recipientId, UserKeyPair senderKeys) throws ServerException, EncodeDecodeException, GeneralSecurityException, InvalidPhraseException, IOException, ValidationException {
       JSONObject externalIDResponse = e2EEncryption.convertExternalId(externalID, senderKeys.getAddress());
       String dataID = externalIDResponse.get("dataId").toString();
       return shareData(dataID,recipientId,senderKeys);
    }

    /**
     * Shares the file either with other accounts from the network, that the user already have in contacts, or
     * by providing an email. With the email-share it also returns a link that sends a secret code to the email.
     * Only with the possession of this code can the contents of the share be decrypted.
     * <p>
     * This method is being used in execSelection()
     *
     * @param dataId      file's chain ID
     * @param recipientId recipient(s) chain ID
     * @param senderKeys  user/sender's key pair
     * @return a JSON obj containing the shared file
     */

    public JSONObject shareData(String dataId, String recipientId, UserKeyPair senderKeys, UserKeyPair recipientsEmailLinkKeyPair, UserKeyPair enctryptionEmailKeyPair, String execFileSelectionHash) throws ServerException, EncodeDecodeException, GeneralSecurityException, InvalidPhraseException, IOException, ValidationException {
        boolean isEmailShare;
        isEmailShare = recipientId.contains("@");
        String[] recipientQuerySpecific = e2EEncryption.recipientCheck(recipientId);

        String recipientType = recipientQuerySpecific[0];
        String requestType = recipientQuerySpecific[1];

        //providing that the right API is called
        String getUrl = e2EEncryption.getEndpointUrl("share/credentials", "&dataId=" + dataId + "&" + recipientType + "=" + recipientId);
        LOGGER.fine("credentials/share get request " + getUrl);
        String getShareResponse = e2EEncryption.getRequest(getUrl);
        // Share response is going to give back data either for email or for an identity share
        LOGGER.fine("Share res " + getShareResponse);

        JSONObject shareResData = new JSONObject(getShareResponse);
        JSONObject shareRes = new JSONObject(shareResData.get("data").toString());

        // if the server is OK and gave back the correct data
        if (shareRes.get("dataId").toString().equals(dataId)) {
            //the encryption sent contains pub key of the receiver, if is to be to an identity
            JSONObject encryption = new JSONObject(shareRes.get("encryption").toString());

            //can go into a method
            String encryptedPassA = encryption.get("encryptedPassA").toString();
            String pubKeyA = encryption.get("pubKeyA").toString();
            String decryptedPassword = e2EEncryption.decryptDataWithPublicAndPrivateKey(encryptedPassA, pubKeyA, senderKeys.getPrivateEncKey());
            String syncPassHash = e2EEncryption.getHash(decryptedPassword);
            String recipientEncrKey = recipientsEmailLinkKeyPair.getPublicEncKey();

            EncryptedDataWithPublicKey reEncryptedPasswordInfo = e2EEncryption.encryptDataToPublicKeyWithKeyPair(decryptedPassword, recipientEncrKey, senderKeys);

            String senderId = senderKeys.getAddress();
            String trailHash = e2EEncryption.getHash(dataId + senderId + requestType + recipientId);
            String trailHashSignatureHash = e2EEncryption.getHash(e2EEncryption.signMessage(trailHash, senderKeys));

            // can go into a method
            SortedMap<String, Object> createShare = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            createShare.put("userId", senderId);
            createShare.put("dataId", dataId);
            createShare.put("requestId", defaultRequestId);
            createShare.put("requestType", requestType);
            createShare.put("requestBodyHashSignature", "NULL");
            createShare.put("trailHash", trailHash);
            createShare.put("trailHashSignatureHash", trailHashSignatureHash);
            //TODO: instead of recipientId as key i will have recipientType
            createShare.put(recipientType, recipientId);
            createShare.put("payload", "");

            SortedMap<String, Object> encrpt = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            encrpt.put("senderEncrKey", senderKeys.getPublicEncKey());
            encrpt.put("syncPassHash", syncPassHash);
            encrpt.put("encryptedPassA", reEncryptedPasswordInfo.getPayload());

            createShare.put("encryption", encrpt);

            String requestBodyHash = e2EEncryption.signMessage(e2EEncryption.getRequestHashJSON(createShare), senderKeys);

            createShare.put("requestBodyHashSignature", requestBodyHash);

            JSONObject jsCreateShare = new JSONObject(createShare);
            String postUrl = e2EEncryption.getEndpointUrl("share/create");

            String serverPostResponse = e2EEncryption.post(postUrl, jsCreateShare);

            //TODO: serverPostResponce and result could be null
            JSONObject postResponse = new JSONObject(serverPostResponse);
            LOGGER.info("Share POST to server encryption info " + jsCreateShare.toString(1));
            LOGGER.fine("Server responds to user device POST " + postResponse.toString());
            JSONObject serverResult = new JSONObject(postResponse.toString());
            if (!serverResult.get("data").toString().startsWith("{")) {
                String[] message = serverResult.get("data").toString().split(",");
                for (int i = 0; i < message.length; i++) {
                    //This message should stay
                    LOGGER.info(message[i]);
                }
                return new JSONObject("Sending interupted");
            } else {

                JSONObject result = new JSONObject(serverResult.get("data").toString());

                //generating email keys and shareable link
                if (isEmailShare) {
                    String shareUrl = generateEmailShareUrl(senderKeys, recipientsEmailLinkKeyPair, enctryptionEmailKeyPair, execFileSelectionHash);
                    result.put("shareUrl", shareUrl);
                }
                return result;
            }
        }
        return new JSONObject("{\"message\":{\"EN\":\"The sending has been interuppted.\"}}");
    }

    public JSONObject shareDataWithExternalID(String externalID, String recipientId, UserKeyPair senderKeys, UserKeyPair recipientsEmailLinkKeyPair, UserKeyPair enctryptionEmailKeyPair, String execFileSelectionHash) throws ServerException, EncodeDecodeException, GeneralSecurityException, InvalidPhraseException, IOException, ValidationException {
        JSONObject externalIDResponse = e2EEncryption.convertExternalId(externalID, senderKeys.getAddress());
        String dataID = externalIDResponse.get("dataId").toString();
        return shareDataWithExternalID(dataID,recipientId,senderKeys, recipientsEmailLinkKeyPair,enctryptionEmailKeyPair, execFileSelectionHash);
    }

    /**
     * This method will generate a link that will provide a one-time access to specific file. With privacy by design
     * in mind, the link would be able to show the file to the user after they enter a code that is sent to the provided
     * email
     *
     * @param shareResult  this an object containing a selectionHash - reference to the recipient and file that's
     *                     being sent
     * @param keyPair      - the key pair of the sender
     * @param emailKeyPair - a temporary key pair that is created for the recipient.
     * @return String, link, that can be given to the receiver to open, having that they can get the security code from
     * the provided email.
     */

    private String generateEmailShareUrl(JSONObject shareResult, UserKeyPair keyPair, UserKeyPair emailKeyPair) {
        String generatedShareUrl = null;

        if (shareResult.get("selectionHash").toString() == null) {
            LOGGER.info("Unable to create email share selection hash. Contact your service provider.");
            return new String("Unable to create email share selection hash. Contact your service provider.");
        } else {

            String selectionHash = shareResult.get("selectionHash").toString();

            generatedShareUrl = baseUrl + "/view/email/" + selectionHash;
            SortedMap<String, Object> queryObj = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            queryObj.put("selectionHash", selectionHash);
            queryObj.put("pubKey", emailKeyPair.getPublicSignKey());
            queryObj.put("pubEncKey", emailKeyPair.getPublicEncKey());
            queryObj.put("shareUrl", generatedShareUrl);
            queryObj.put("requestBodyHashSignature", "NULL");

            String requestBodyHash = e2EEncryption.signMessage(e2EEncryption.getRequestHashJSON(queryObj), keyPair);
            queryObj.put("requestBodyHashSignature", requestBodyHash);

            // Stringified for harder readability
            String query = e2EEncryption.getObjectIntoByte64(queryObj);

            SortedMap<String, Object> fragmentObj = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

            fragmentObj.put("secretKey", emailKeyPair.getPrivateSignKey());
            fragmentObj.put("secretEncKey", emailKeyPair.getPrivateEncKey());

            String fragment = e2EEncryption.getObjectIntoByte64(fragmentObj);

            generatedShareUrl = generatedShareUrl + "?q=" + query + "#" + fragment;

            return generatedShareUrl;
        }
    }

    /**
     * This method will generate a link that will provide a one-time access to specific file. With privacy by design
     * in mind, the link would be able to show the file to the user after they enter a code that is sent to the provided
     * email
     *
     * @param senderKeys                - the key pair of the sender.
     * @param recipientEmailLinkKeyPair - a temporary key pair that is created for the recipient.
     * @param execFileSelectionHash     - a hash provided for the multiple files being sent as a pack.
     * @return String, link, that can be given to the receiver to open, having that they can get the security code from
     * the provided email.
     */

    private String generateEmailShareUrl(UserKeyPair senderKeys, UserKeyPair recipientEmailLinkKeyPair, UserKeyPair encryptionEmailLinkKeyPair, String execFileSelectionHash) throws GeneralSecurityException, InvalidPhraseException, IOException {
        String generatedShareUrl = null;
        String selectionHash = "";

        if (execFileSelectionHash == null) {
            LOGGER.info("Unable to create email share selection hash. Contact your service provider.");
            return new String("Unable to create email share selection hash. Contact your service provider.");
        } else {
            selectionHash = execFileSelectionHash;


            generatedShareUrl = baseUrl + "/view/email/" + selectionHash;
            SortedMap<String, Object> queryObj = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            queryObj.put("selectionHash", selectionHash);
            queryObj.put("pubKey", recipientEmailLinkKeyPair.getPublicSignKey());
            queryObj.put("pubEncKey", recipientEmailLinkKeyPair.getPublicEncKey());
            queryObj.put("shareUrl", generatedShareUrl);
            queryObj.put("requestBodyHashSignature", "NULL");


            String requestBodyHash = e2EEncryption.signMessage(e2EEncryption.getRequestHashJSON(queryObj), senderKeys);
            queryObj.put("requestBodyHashSignature", requestBodyHash);


            // Stringified for harder readability
            String query = e2EEncryption.getObjectIntoByte64(queryObj);

            SortedMap<String, Object> fragmentObj = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

            fragmentObj.put("secretKey", recipientEmailLinkKeyPair.getPrivateSignKey());
            fragmentObj.put("secretEncKey", recipientEmailLinkKeyPair.getPrivateEncKey());

            String fragment = e2EEncryption.getObjectIntoByte64(fragmentObj);

            generatedShareUrl = generatedShareUrl + "?q=" + query + "#" + fragment;

            JSONObject result = new JSONObject();

            result.put("shareUrl", generatedShareUrl);

            EncryptedDataWithPublicKey encryptedShareUrl = e2EEncryption.encryptDataToPublicKeyWithKeyPair(generatedShareUrl, encryptionEmailLinkKeyPair.getPublicEncKey(), senderKeys);

            SortedMap<String, Object> emailSelectionsObj = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

            emailSelectionsObj.put("selectionHash", selectionHash);
            emailSelectionsObj.put("pubKey", encryptionEmailLinkKeyPair.getPublicSignKey());
            emailSelectionsObj.put("pubEncKey", encryptionEmailLinkKeyPair.getPublicEncKey());
            emailSelectionsObj.put("encryptedUrl", encryptedShareUrl.getPayload());

            JSONObject emailSelecObj = new JSONObject(emailSelectionsObj);
            String submitUrl = e2EEncryption.getEndpointUrl("email/share/create");
            String submitRes = e2EEncryption.post(submitUrl, emailSelecObj);

            JSONObject serverResponse = new JSONObject(submitRes);

            JSONObject submitResData = new JSONObject(serverResponse.get("data").toString());
            LOGGER.info("Server returns result" + submitResData);

            try {
                if (serverResponse.get("status").equals("ERROR")) {
                    throw new Exception("Something went wrong with execSelection share");
                }
            } catch (Exception e) {
                e.getMessage();
            }
            return generatedShareUrl;
        }
    }

    /**
     * This function is going to be called upon uploading information and 'store' it on the blockchain
     *
     * @param data - this will be the name stored on the platform
     * @return server's response whether the file has been uploaded
     */
    public String store(String data,String dataName, String dataExtension, UserKeyPair keyPair) throws IOException {
        FileObj obj = new FileObj();
        obj.setPayload(data);
        obj.setName(dataName);
        obj.setDataExtention(dataExtension);
        try {
            FileToUpload file = e2EEncryption.getFileUploadData(obj, keyPair);
            return e2EEncryption.uploadFile(file);
        } catch (Exception e) {
            e.printStackTrace();
            LOGGER.info("Error. " + e.getMessage());
        }
        return null;
    }

    /**
     * This function is going to be called upon uploading information and 'store' it on the blockchain
     *
     * @param data - this will be the name stored on the platform
     * @return server's response whether the file has been uploaded
     */
    public String storeWithExternalID(String data,String dataName, String dataExtension, String externalID, UserKeyPair keyPair) throws IOException {
        FileObj obj = new FileObj();
        obj.setPayload(data);
        obj.setName(dataName);
        obj.setDataExtention(dataExtension);
        try {
            FileToUpload file = e2EEncryption.getFileUploadData(obj, keyPair);
            e2EEncryption.saveExternalId(externalID,keyPair.getAddress(),file.getEncrypt().getDataHash());
            return e2EEncryption.uploadFile(file);
        } catch (Exception e) {
            e.printStackTrace();
            LOGGER.info("Error. " + e.getMessage());
        }
        return null;
    }


    /**
     * This function is going to be called upon uploading a file and 'store' it on the blockchain
     *
     * @param fileNameFromPath - this will be the name stored on the platform
     * @return server's response whether the file has been uploaded
     */
    public String storeFile(String fileNameFromPath, UserKeyPair keyPair) throws IOException {
        FileObj obj = new FileObj();
        byte[] array;
        String fileContent = "";
        array = Files.readAllBytes(Paths.get(fileNameFromPath));
        fileContent = Base64.getEncoder().encodeToString(array);
        obj.setPayload(fileContent);
        int indexName = fileNameFromPath.lastIndexOf("/");
        String name;
        if (indexName > 0) {
            name = fileNameFromPath.substring(indexName);
        } else {
            name = fileNameFromPath;
        }
        String dataExtension;
        int index = name.lastIndexOf(".");
        if (index > 0) {
            dataExtension = name.substring(index);
            name = name.substring(0, index);
        } else {
            dataExtension = ".unknown";
        }
        obj.setName(name);
        obj.setDataExtention(dataExtension);

        try {
            FileToUpload file = e2EEncryption.getFileUploadData(obj, keyPair);
            return e2EEncryption.uploadFile(file);
        } catch (Exception e) {
            e.printStackTrace();
            LOGGER.info("Error. " + e.getMessage());
        }
        return null;
    }

    /**
     * This function is going to be called upon uploading a file and 'store' it on the blockchain with
     * client specific ID.
     *
     * @param fileNameFromPath - this will be the name stored on the platform
     * @param externalID - the id provided by the client
     * @return server's response whether the file has been uploaded
     */
    public String storeFileWithExternalID(String fileNameFromPath, UserKeyPair keyPair, String externalID) throws IOException {
        FileObj obj = new FileObj();
        byte[] array;
        String fileContent = "";
        array = Files.readAllBytes(Paths.get(fileNameFromPath));
        fileContent = Base64.getEncoder().encodeToString(array);
        obj.setPayload(fileContent);
        int indexName = fileNameFromPath.lastIndexOf("/");
        String name;
        if (indexName > 0) {
            name = fileNameFromPath.substring(indexName);
        } else {
            name = fileNameFromPath;
        }
        String dataExtension;
        int index = name.lastIndexOf(".");
        if (index > 0) {
            dataExtension = name.substring(index);
            name = name.substring(0, index);
        } else {
            dataExtension = ".unknown";
        }
        obj.setName(name);
        obj.setDataExtention(dataExtension);

        try {
            FileToUpload file = e2EEncryption.getFileUploadData(obj, keyPair);
            e2EEncryption.saveExternalId(externalID,keyPair.getAddress(),file.getEncrypt().getDataHash());
            return e2EEncryption.uploadFile(file);
        } catch (Exception e) {
            e.printStackTrace();
            LOGGER.info("Error. " + e.getMessage());
        }
        return null;
    }

    /**
     * Gets information about a file, which is owned by/shared to the user and opens it
     *
     * @param dataChainId file's chain ID
     * @param keyPair     user's key pair
     * @return the contents of the file in human readable form
     */
    public JSONObject openFile(String dataChainId, UserKeyPair keyPair) throws GeneralSecurityException, EncodeDecodeException, IOException, ExternalKeyPairException, ServerException, KeyExchangeException, ValidationException {

        JSONObject credentialsResponse = e2EEncryption.prepare(dataChainId, keyPair.getPublicSignKey());
        JSONObject scanResult = reEncrypt(keyPair.getPublicSignKey(), dataChainId, keyPair);
        if (scanResult.get("userId").toString() != null) {
//            polling server for pass to decrypt message
            return e2EEncryption.poll(credentialsResponse, keyPair.getPublicEncKey());
        } else {
            throw new Error("Unable to decrypt file");
        }
    }

    public JSONObject openFileWithExternalID(String externalID, UserKeyPair keyPair) throws GeneralSecurityException, EncodeDecodeException, IOException, ExternalKeyPairException, ServerException, KeyExchangeException, ValidationException {
        JSONObject externalIDResponse = e2EEncryption.convertExternalId(externalID, keyPair.getAddress());
        String dataID = externalIDResponse.get("dataId").toString();
        return openFile(dataID,keyPair);
    }

        /**
         * This function is to for the user to put a signature with their private key on file or message
         * that they verify or validate to be authentic
         *
         * @param dataId      - the file or message to be signed
         * @param recipientId - file or message's owner
         * @param keyPair     - signer's key pair
         * @return the result from the server - empty string for success, otherwise an error
         */

    public JSONObject signFile(String dataId, String recipientId, UserKeyPair keyPair) throws IOException {
        String userId = keyPair.getAddress();

        //TODO change them into their should be thing
//        String trailExtraArgs = null;

//        dataId = processExternalId(dataId, userId, isExternal);

        String requestType = "sign";
        String trailHash = e2EEncryption.getHash(dataId + userId + requestType + recipientId);

        SortedMap<String, Object> signObj = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        signObj.put("dataId", dataId);
        signObj.put("userId", userId);
        signObj.put("requestId", defaultRequestId);
        signObj.put("recipientId", recipientId);
        signObj.put("requestType", requestType);
        signObj.put("requestBodyHashSignature", "NULL");
        signObj.put("trailHash", trailHash);
        signObj.put("trailHashSignatureHash", e2EEncryption.getHash(e2EEncryption.signMessage(trailHash, keyPair)));

        String requestBodyHashSignature = e2EEncryption.signMessage(e2EEncryption.getRequestHashJSON(signObj), keyPair);

        signObj.put("requestBodyHashSignature", requestBodyHashSignature);

        JSONObject jsSignObject = new JSONObject(signObj);

        String postUrl = e2EEncryption.getEndpointUrl("signature/create");
        LOGGER.info("dataSign " + jsSignObject.toString(1));

        String serverPostResponse = e2EEncryption.post(postUrl, jsSignObject);

        JSONObject serverPostResData = new JSONObject(serverPostResponse);
        LOGGER.info("Server responds to data sign POST" + serverPostResData.get("data").toString());
        JSONObject serverPostData = new JSONObject(serverPostResData.get("data").toString());
        return serverPostData;
    }

    public JSONObject signFileWithExternalID(String externalID, String recipientId, UserKeyPair keyPair) throws IOException, ServerException {
        JSONObject externalIDResponse = e2EEncryption.convertExternalId(externalID, keyPair.getAddress());
        String dataID = externalIDResponse.get("dataId").toString();
        return signFile(dataID,recipientId, keyPair);
    }

        /**
         * Function to open/share/mobile open to a particular selection of files
         *
         * @param selection hash of selection of files
         * @param keyPair   user's key pair
         * @return a collection with hashes of the files that have been manipulated
         */
    public ArrayList<ResultFileObj> execSelection(String selection, UserKeyPair keyPair) throws ServerException, GeneralSecurityException, ExternalKeyPairException, IOException, EncodeDecodeException, KeyExchangeException, ValidationException, InvalidPhraseException {
        ArrayList<ResultFileObj> result = new ArrayList<>();
        // check if we have a selection or an id
        if (selection.indexOf(":") > 0) {

            String[] actionSelectionHash = selection.split(":");
            String action = actionSelectionHash[0];
            String selectionHash = actionSelectionHash[1];
            String selectionResult = e2EEncryption.getSelected(selectionHash);

            LOGGER.info("selection result " + selectionResult);

            JSONObject selectionResData = new JSONObject(selectionResult);

            JSONObject selectionRes = new JSONObject(selectionResData.get("data").toString());
            LOGGER.fine("--------");
            LOGGER.fine(selectionRes.toString(1));
            LOGGER.fine("-------");


            if (selectionRes.get("selectionHash").toString() != null) {
                String[] recipients;
                if (action.equals("se")) {
                    recipients = selectionRes.get("usersEmails").toString().split(",");
                } else {
                    recipients = selectionRes.get("usersIds").toString().split(",");
                }
                for (int i = 0; i < recipients.length; i++) {
                    recipients[i] = recipients[i].replace("[", "");
                    recipients[i] = recipients[i].replace("]", "");
                    recipients[i] = recipients[i].replace("\"", "");
                }

                String[] files = selectionRes.get("dataIds").toString().split(",");
                for (int i = 0; i < files.length; i++) {
                    files[i] = files[i].replace("[", "");
                    files[i] = files[i].replace("]", "");
                    files[i] = files[i].replace("\"", "");
                }

                UserKeyPair emailSharePubKeys = null;
                UserKeyPair recipientsEmailLinkKeyPair = null;
                if (action.equals("se")) {
                    recipientsEmailLinkKeyPair = e2EEncryption.newKeyPair(null);
                    String getUrl = e2EEncryption.getEndpointUrl("email/info", "&selectionHash=" + selectionHash);
                    String serverRes = e2EEncryption.getRequest(getUrl);
                    JSONObject serverResJSON = new JSONObject(serverRes);
                    LOGGER.info("email/info res " + serverResJSON.toString(1));
                    JSONObject serverResponse = new JSONObject(serverResJSON.get("data").toString());

                    try {
                        if (serverResJSON.get("status").equals("ERROR")) {
                            throw new Exception((String) serverResponse.get("data"));
                        }
                    } catch (Exception e) {
                        e.getMessage();
                    }

//                  TODO: have a check whether everything in the data is there

//                    if (serverResponse.get("data") == null){
//                        if ()isNullAny(serverResponse.data.pubKey, serverResponse.data.pubEncKey)
//                    }) {
//                        throw new Error('Invalid email selection server response.');
//                    }

                    emailSharePubKeys = new UserKeyPair(serverResponse.get("pubKey").toString(), serverResponse.get("pubEncKey").toString());
                }


                if (recipients.length != files.length) {   // the array sizes must be equal
                    throw new Error("Invalid selection format.");
                }
                for (int i = 0; i < files.length; i++) {  // iterate open each entry from the array
                    if (action.equals("op")) {
                        if (!keyPair.getPublicSignKey().equals(recipients[i])) {
                            LOGGER.fine("selection entry omitted " + recipients[i] + ":" + files[i]);
                            continue;                             // skip entries that are not for that keypair
                        }
                        if (keyPair.getPrivateEncKey() != null) {
                            LOGGER.fine("selection entry added " + recipients[i] + ":" + files[i]);
                            JSONObject fileContent = openFile(files[i], keyPair);
                            result.add(new ResultFileObj(files[i], fileContent));

                        } else {
                            //creating the json object to pass to pollForFile
                            JSONObject fileCont = new JSONObject();
                            fileCont.put("dataId", files[i]);
                            fileCont.put("userId", recipients[i]);

                            JSONObject fileContent = e2EEncryption.poll(fileCont, keyPair.getPublicEncKey());

                            result.add(new ResultFileObj(files[i], fileContent));

                        }
                    } else if (action.equals("re")) {
                        if (!keyPair.getAddress().equals(recipients[i])) {
                            LOGGER.fine("selection entry omitted " + recipients[i] + ":" + files[i]);
                            continue;                      // skip entries that are not for that keypair
                        }
                        LOGGER.fine("selection entry added " + recipients[i] + ":" + files[i]);
                        JSONObject scanResult = reEncrypt(recipients[i], files[i], keyPair);

                        result.add(new ResultFileObj(files[i], scanResult));

                    } else if (action.equals("sh")) {

                        JSONObject shareResult = shareData(files[i], recipients[i], keyPair);

                        result.add(new ResultFileObj(files[i], shareResult));

                    } else if (action.equals("se")) {

                        JSONObject shareResult = shareData(files[i], recipients[i], keyPair, recipientsEmailLinkKeyPair, emailSharePubKeys, selectionHash);

                        result.add(new ResultFileObj(files[i], shareResult));

                    } else if (action.equals("sg")) {

                        JSONObject signResult = signFile(files[i], recipients[i], keyPair);

                        result.add(new ResultFileObj(files[i], signResult));
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

    /**
     * This method asks for the file ID in the chain, the user's keys and the directory to which the file to be
     * downloaded to
     *
     * @param fileChainID the file's chain ID
     * @param keys        user's keys
     * @param directory   directory to which the user wants to download the file
     */

    public void downloadFile(String fileChainID, UserKeyPair keys, String directory) throws GeneralSecurityException, ExternalKeyPairException, KeyExchangeException, IOException, EncodeDecodeException, ServerException, ValidationException {
        JSONObject jss = openFile(fileChainID, keys);
        File dir = new File(directory);
        if (!dir.exists()) {
            if (dir.mkdir()) {
                LOGGER.info("Directory is created!");
            } else {
                LOGGER.info("Failed to create directory!");
            }
        }

        // decodes the file and puts it together
        byte[] decodedFile = Base64.getDecoder().decode((String) jss.get("payload"));
        File newFile = new File((String) directory + jss.get("dataName") + jss.get("dataExtension"));

        try {
            OutputStream os = new FileOutputStream(newFile);
            os.write(decodedFile);
            LOGGER.info("Write bytes to file.");
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void downloadFileWithExternalID(String externalID, UserKeyPair keys, String directory) throws GeneralSecurityException, ExternalKeyPairException, KeyExchangeException, IOException, EncodeDecodeException, ServerException, ValidationException {
        JSONObject jss = openFileWithExternalID(externalID, keys);
        File dir = new File(directory);
        if (!dir.exists()) {
            if (dir.mkdir()) {
                LOGGER.info("Directory is created!");
            } else {
                LOGGER.info("Failed to create directory!");
            }
        }

        // decodes the file and puts it together
        byte[] decodedFile = Base64.getDecoder().decode((String) jss.get("payload"));
        File newFile = new File((String) directory + jss.get("dataName") + jss.get("dataExtension"));

        try {
            OutputStream os = new FileOutputStream(newFile);
            os.write(decodedFile);
            LOGGER.info("Write bytes to file.");
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
