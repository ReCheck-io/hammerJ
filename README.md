[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.recheck-io/hammerJ/badge.svg)](https://search.maven.org/artifact/io.github.recheck-io/hammerJ)  [![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/ReCheck-io/hammerJ/blob/master/LICENSE.txt) ![](https://github.com/Recheck-io/hammerJ/workflows/maven%20build/badge.svg) [![Known Vulnerabilities](https://snyk.io/test/github/Recheck-io/hammerJ/badge.svg)](https://snyk.io/test/github/Recheck-io/hammerJ)

# Encryption library used for blockchain workflow. 
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

#### How can it be used?
 
To securely transfer a file or a message across servers and browsers to the receiver, without the possibility of anyone but the receiver to unlock the contents of your package. 
- Upload an encrypted file to a server (the server cannot see anything but the hash of the file) 
- Decrypt a file from the server and download it locally
- Share а file with other people in the network (in process)

#### What does it give ? 

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
