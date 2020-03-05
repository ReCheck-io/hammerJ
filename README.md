[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.recheck-io/hammerJ/badge.svg)](https://search.maven.org/artifact/io.github.recheck-io/hammerJ)  [![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/ReCheck-io/hammerJ/blob/master/LICENSE.txt) ![](https://github.com/Recheck-io/hammerJ/workflows/maven%20build/badge.svg)

# Encryption library with two PKI key pairs. 
HammerJ is a Java encryption library that is used for end to end encryption. It is used to encrypt a message or file and securely send it across the internet to the receiver without the possibility of anyone but the sender and the receiver to know what is being sent. This library is using two PKI keypairs as well as symmetric encryption. We’ve implemented TweetNacl Fast standard methods. 

The expected workflow is where there will be a mobile app and client separately established. Only the mobile app will be able to hold the user’s key pairs. Meaning that it will be used for signing and encrypting/decrypting messages.  

### Usage
Keep in mind that you have **to select the latest version** when importing the library to your project. It is written at the start of the README file. 
#### maven 

```
<dependency>
  <groupId>io.github.recheck-io</groupId>
  <artifactId>hammerJ</artifactId>
  <version>x.x.x</version>
</dependency>
```

#### gradle 
```
implementation 'io.github.recheck-io:hammerJ:x.x.x'
```

### Getting started 

#### Creating a key pair
The first thing you have to do is to create a key pair. They are used in all asymmetric encryption and user related methods. 

```
 App app = new App();
        UserKeyPair keys= null;
        String seedphrase = "";
        try {
           keys = app.generateAkKeyPair(seedphrase);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
```
The key pair can be generated in two ways: 
- First, when it is a new user and there is no seedphrase. Such will be generated using the diceware alogith - creating 12 easy to remember random words. 
- Second, from a seedphrase.

It is **highly recommended** for user to **write down and keep this phrase somewhere safe, as it is the only way to have access to their key pair.**

#### Main functions
Whether you would like to use ReCheck's service, or build your own server that is up to you. If you are to use our back-end, than these are the steps you should follow: 

##### **Getting a token**

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
app.login(keys, challenge);
```

##### Upload
Once the user has logged, one way or the other, they can upload a file. 

The file has to be sent as a JSON obj, because it is sent via https and our server is only accepting this type of information.

```
    public void upload(App ap, String filename, String userChainId, String userChainIdPubKey){
        byte[] array;
        String fileContent = "";
        try {
            array = Files.readAllBytes(Paths.get("Greedy4.pdf"));
            fileContent = Base64.getEncoder().encodeToString(array);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        String upload =  ap.store(filename, fileContent, userChainId, userChainIdPubKey);
        
        // to print the response from the server 
        System.out.println(upload);
    }

```


##### Download
The user can download a file, that has been uploaded by or shared to them. The directory is left to be hardcoded or left as a user choice, depending on the higher level of implementation. 

```
String directory = "downloads/";
ap.downloadFile(fileChainID, keys, directory);
```


### hammerJ is useful encryption library

#### It can be used for: 
 
To securely transfer a file or a message across servers and browsers to the receiver, without the possibility of anyone but the receiver to unlock the contents of your package. 
- Upload an encrypted file to a server (the server cannot see anything but the hash of the file) 
- Decrypt a file from the server and download it locally
- Share а file with other people in the network (in process)

#### It gives:  

- API to work with Ethereum blockchain
- API to work with Aeternity blockchain
- Cryptographic methods to encrypt and decrypt, both in a symmetric and asymmetric manner. 

#### Why should anybody use it ? 

- Easy plug and play implementation to Java and Android. 
- The library can be used for any PKI workflow as it automatically creates a memorable phrase out of which creates two key pairs to work with.  



### Resources

#### JBlake2
- Origin: https://github.com/kocakosm/jblake2
- License: **GNU Lesser General Public License**

#### Scrypt 
- Origin: https://github.com/wg/scrypt
- License: **Apache License 2.0**

#### TweetNaCl-java
- Origin: https://github.com/InstantWebP2P/tweetnacl-java
- License: **MIT Copyright(2014-2017) by tom zhou, iwebpp@gmail.com**

#### Web3J
- Origin: https://github.com/web3j/web3j
- License: **Apache License 2.0** 


### Created by Recheck BV.

### License: MIT 
