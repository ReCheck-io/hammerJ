[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.recheck-io/hammerJ/badge.svg)](https://search.maven.org/artifact/io.github.recheck-io/hammerJ)  [![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/ReCheck-io/hammerJ/blob/master/LICENSE.txt) ![](https://github.com/Recheck-io/hammerJ/workflows/maven%20build/badge.svg)  [![Website recheck.io](https://img.shields.io/badge/Website-recheck.io-brightgreen.svg)](https://recheck.io/)<a href="https://discord.gg/3KwFw72"><img src="https://img.shields.io/discord/675683560673509386?logo=discord" alt="chat on Discord"></a>

# Encryption library with two PKI key pairs. 
HammerJ is a Java encryption library implementation of end-to-end encryption protocol. Through this software one can securely send a message or file across the internet to the receiver without the possibility of anyone but the sender and the receiver to know what is being sent. This library is using two PKI keypairs as well as symmetric encryption. We’ve implemented TweetNacl Fast standard methods. 

The expected workflow is where there will be a mobile app and client separately established. Only the mobile app will be able to hold the user’s key pairs. Meaning that it will be used for signing and encrypting/decrypting messages.

The protocol is the following: 
![protocol](docs/protocol.png)  

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
The main methods exported for usage are a few. To see more detailed explanations and examples [click here](docs/index.md).

- **newKeyPair ( seedphrase )** - where the seedphrase is String.
- **login ( keys, challenge )** - the user's keyPair and the challenge to enter the GUI, if the user wants. This function gives the user a token with which to operate in the service. 
- **openFile ( fileChainID, keys )** - will get the payload of the respective file from the service. 
- **downloadFile ( fileChainID, keys, directory )** - will convert the payload taken from _openFile()_. for the file, have the filename and suffix from the specified name and suffix uploaded and convert accordingly into the specified local directory. 
- **store ( dataPath, keys )** - uploads the file on the server. You have to specify the full path of the file, or just the name, if the file is in the program's folder and the keys of the user
- **execSelection ( selectionHash, keys )** - this method executes several actions. Depending on the hash, it can open, share or sign a file. 

### hammerJ can be used for: 
 
To securely transfer a file or a message across servers and browsers to the receiver, without the possibility of anyone but the receiver to unlock the contents of your package. 
- Upload an encrypted file to a server (the server cannot see anything but the hash of the file) 
- Decrypt a file from the server and download it locally
- Share а file with other people in the network 
- Validate the authencity of the data by signing it. 

#### It gives:  

- API to work with Ethereum blockchain
- API to work with Aeternity blockchain
- Cryptographic methods to encrypt and decrypt, both in a symmetric and asymmetric manner. 

#### Why should anybody use it ? 

- Easy plug and play implementation to Java and Android. 
- The library can be used for any PKI workflow as it automatically creates a memorable phrase out of which creates two key pairs to work with.  

### Why cryptography 

In the era of Information, everything has a digital representation. Cryptography is the only natural response to protect valuable information. Thus we saw the need to establish an environment with variaty of tools to create a safe path for information to be stored and transferred from A to B. In our [blog post](https://recheck.io/blog/guard-data-integrity/) about guarding your data integrity in business you can learn even more about the essentiality and importance of cryptography in our days. 

### Why blockchain

Business digitalization requires several key properties for the data exchange and storage processes. They are privacy, transparency and integrity. With blockchain as a foundation for data securitization we achieve the required transparency and integrity of business data exchange and accompanying transactions.

Our implementation of data access trailing achieves the privacy aspect of these requirements. It allows transaction participants to securely validate the digital trails without the need of any middleware, but directly querying the blockchain.

This approach can be safely applied within both public and private/consortium installation of blockchain networks, such as Ethereum, Aeternity, Hyperledger Fabric, Factom, EOS.

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
