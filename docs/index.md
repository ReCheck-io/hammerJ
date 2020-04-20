# Getting started 

## Creating a key pair
The first thing you have to do is to create a key pair. They are used in all asymmetric encryption and user related methods. 

```
 HammerJ hammerJ = new HammerJ();
        UserKeyPair keys= null;
        String seedphrase = "";
        try {
           keys = hammerJ.generateAkKeyPair(seedphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
```
The key pair can be generated in two ways: 
- First, when it is a new user and there is no seedphrase. Such will be generated using the diceware alogith - creating 12 easy to remember random words. 
- Second, from a seedphrase.

It is **highly recommended** for user to **write down and keep this phrase somewhere safe, as it is the only way to have access to their key pair.**

## Main functions
Whether you would like to use ReCheck's service, or build your own server that is up to you. If you are to use our back-end, than these are the steps you should follow: 

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
Once the user has logged, one way or the other, they can upload a file. 

The file has to be sent as a JSON obj, because it is sent via https and our server is only accepting this type of information.

```
    public void upload(HammerJ hammerJ, String filename, String userChainId, String userChainIdPubKey){
        byte[] array;
        String fileContent = "";
        try {
            array = Files.readAllBytes(Paths.get("Greedy4.pdf"));
            fileContent = Base64.getEncoder().encodeToString(array);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        String upload =  hammerJ.store(filename, fileContent, userChainId, userChainIdPubKey);
        
        // to print the response from the server 
        System.out.println(upload);
    }

```


### Download
The user can download a file, that has been uploaded by or shared to them. The directory is left to be hardcoded or left as a user choice, depending on the higher level of implementation. 

```
String directory = "downloads/";
hammerJ.downloadFile(fileChainID, keys, directory);
```


### Share

To share a file, one has to provide a selection hash. 

This selection hash can be obtained in ReCheck web app by selecting the files you want to share and then clicking on the share button. Then you will receive a QR code with similar String : 

```s:0xff7ebbfb2cdf0ea4429491e8cd48e427bc3422c0801153d355d5ef12937e6ac6```

```
ArrayList<ResultFileObj> res = hammerJ.execSelection("s:0xff7ebbfb2cdf0ea4429491e8cd48e427bc3422c0801153d355d5ef12937e6ac6", keys);
```

This selection is created by having two arrays. The first array is with __hash IDs of the data/files in the blockchain__. The second is with __the recepients IDs__. The selection hash is then created by stringifying and then hashing (array[files] + array[userIDs]).

If you don't want to use the ReCheck services, you can create the selection hash by using the **selectFiles()** method. 


The receiver(s) will have the new file(s) as separate inputs. To open those files, one will receive a QR code with similar data: 
```o:0xf77ebbfb2cdf0ea4429491e8cd48e427bc3422c0801153d355d5ef12937e6ac6```

The method **execSelection()** can take three types of selection, that are indicated in the start of the selection string. 
- op - open the selection
- re - mobile open the selection  
- sh - share the selection
- sn - sign the selection/file
```
ArrayList<ResultFileObj> res = hammerJ.execSelection("o:0xf77ebbfb2cdf0ea4429491e8cd48e427bc3422c0801153d355d5ef12937e6ac6", keys);
```
