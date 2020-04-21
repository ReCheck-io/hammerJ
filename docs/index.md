# Getting started 

## Creating a key pair
The first thing you have to do is to create a key pair. They are used in all asymmetric encryption and user related methods. 

```
 HammerJ hammerJ = new HammerJ();
        UserKeyPair keys= null;
        String seedphrase = "";
        try {
           keys = hammerJ.newKeyPair(seedphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
```
The key pair can be generated in two ways: 
- First, when it is a new user and there is no seedphrase (empty string or null ). Such will be generated using the diceware algorithm - creating 12 easy to remember random words. 
- Second, from a seedphrase - creating specific key pair.

It is **highly recommended** for user to **write down and keep this phrase somewhere safe, as it is the only way to have access to their key pair.**

## Main functions


### **Getting a token**

To use our service, you will need a temporary token that recognises your account and makes the connection between the client and the server for the session. There are two ways to get a token with and without entering the web GUI: 
  - with entering the web GUI - then challenge parameter has to be matching the QR code/text from the login page. It is intended for the user to login with their mobile app.
  - without entering the web GUI - then the challenge parameter can be taken as get request from ``` login/challange```
    ```
    String getChallengeUrl = getEndpointUrl("login/challenge");
    String challengeResponce = getRequest(getChallengeUrl);
    JSONObject js = new JSONObject(challengeResponce);
    String challenge = js.get("challenge").toString();
    ``` 


```
hammerJ.login(keys, challenge);
```

### Upload
Once the user got a token they can upload a file. 

The file is sent as a JSON obj, because it is sent via https and our server is only accepting this type of information.

The method requires a filepath (or just the file name if the file is in the program's folder) and the user's key pair. 

```
hammerJ.store(filePath, keys);
```


### Download
The user can download a file, that has been uploaded by or shared to them. The directory is left as a user's choice. 

```
String directory = "downloads/";
hammerJ.downloadFile(fileChainID, keys, directory);
```

The key thing in this download is that it will download the file as byte array from the server and then compiles it into a whole without adding any meta data, as sometimes other services may do.

### Share, Sign, Visualizing on the service 

All of those actions are done through one method - **execSelection( selectionHash, keys )**

- re - mobile open the selection  
- sh - share the selection
- sg - sign the selection/file

#### Share
To share a file, one has to provide a selection hash with the **sh:** as preffix. 

This selection hash can be obtained in ReCheck web app by selecting the files you want to share and then clicking on the share button. Then you will receive a QR code with similar String : 

```sh:0xff7ebbfb2cdf0ea4429491e8cd48e427bc3422c0801153d355d5ef12937e6ac6```

```
ArrayList <ResultFileObj> res = hammerJ.execSelection("sh:0xff7ebbfb2cdf0ea4429491e8cd48e427bc3422c0801153d355d5ef12937e6ac6", keys);
```

This selection is created by having two arrays. The first array is with __hash IDs of the data/files in the blockchain__. The second is with __the recepients IDs__. The selection hash is then created by stringifying and then hashing (array[files] + array[userIDs]).

If you don't want to use the ReCheck services, you can create the selection hash by using the **selectFiles()** method. 

#### Visualizing on the service
The receiver(s) will have the new file(s) as separate inputs. To open those files, one will receive a QR code with similar data: 
```re:0xf77ebbfb2cdf0ea4429491e8cd48e427bc3422c0801153d355d5ef12937e6ac6```

The method **execSelection()** can take three types of selection, that are indicated in the start of the selection string. 

```
ArrayList<ResultFileObj> res = hammerJ.execSelection("re:0xf77ebbfb2cdf0ea4429491e8cd48e427bc3422c0801153d355d5ef12937e6ac6", keys);
```

#### Sign
If the user wants to validate or prove the authenticity of a file or message, they can put their **sign** on that file or message. To do this the selection hash has to be with preffix of **sg**

```
ArrayList<ResultFileObj> res = hammerJ.execSelection("sg:0xf77ebbfb2cdf0ea4429491e8cd48e427bc3422c0801153d355d5ef12937e6ac6", keys);
```