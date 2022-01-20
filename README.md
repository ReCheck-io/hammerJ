[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.recheck-io/hammerJ/badge.svg)](https://search.maven.org/artifact/io.github.recheck-io/hammerJ)  [![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/ReCheck-io/hammerJ/blob/master/LICENSE.txt) ![](https://github.com/Recheck-io/hammerJ/workflows/maven%20build/badge.svg)  [![Website recheck.io](https://img.shields.io/badge/Website-recheck.io-brightgreen.svg)](https://recheck.io/)

# About this library 

This is a reference implementation of a protocol for end-to-end encryption with the Recheck services platform. It implements data storage, fetching and validation with a set of keypairs that support ethereum and aeterntiy digital signatures. 

# How it works 

The protocol consists of a client - sending device, server, receiving device and identity device (which is supposed to be your mobile phone ). Between those four entities two sets of PKI key pairs are taking part into sending the data across them. 

The first set is that of the user. It is being created(or more precisely revealed) with the creation of the user's account/wallet. With it, the user can operate with the service we provide. Moreover, upon uploading, the client is using this set to encrypt the file that is being uploaded on ReCheck servers. __By doing this we enforce the good practices of privacy by design and cannot read or in fact know anything about your file.__

The browser through which a user is acting with the data is treated like an additional user with its own keypair, thus providing extra layer of interactive authentication while every operation is still under the control of the user with his own keypair.

This way the private key of the user never leaves his/her identity device, yet it manages the authentication in the browser.

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
