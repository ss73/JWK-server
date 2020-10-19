# JSON Web Key (JWK) Server example

This is a practical example of a JWK server that is focused on handling Elliptic Curve P-384 keys and signing of JWT tokens.

The example also contains a sample web application bundled with the key server to illustrate how a token can be signed and passed to a second application which verifies the signature and acts on the assertions contained in the token.

The code is developed for learning purposes and is not supposed to be used in production as is. For a production setup, at least the following additional points need to be considered:

* The endpoints that allow uploading of new keys should be protected from unauthorized access. Leaving these endpoints open would allow anyone to upload a key that is trusted for validation
* The endpoints that allow deletion of keys should be protected from unauzhorized access, since that could easily be used for a denial of service attack by simply deleting all keys in the keystore
* The get token endpoint should only be allowed to be called after some initial authentication, and the end client should not be allowed to set the subject of the JWT arbitrarily
* The keystore is kept in a local file that is serialized to disk with every update. In a production setup, the keystore should be stored in a database or similar, with locked down access.
* In a production setup, the endpoints should always require the use of HTTPS. This will allow a client requesting a public key to trust the endpoint origin by examining the server certificate

## Installation

The following pre-requisites are required or recommended:

* Node JS and NPM has to be installed
* Postman is recommended but not necessary
* OpenSSL is recommended but not necessary
  
Running the server:

```
npm install
node index.js
```

## Running the application

Point a browser to: http://localhost:3000

## Postman scripts

Open Postman and import the file ``JWK Keystore.postman_collection.json``

The following tests are defined:

* Generate EC JWK - creates a new JWK key based on the Elliptic Curve P-384. This key is 384 bits and roughly comparable to a symmetric key (e.g. AES) of 192 bits
* Upload PEM key - Uploads an EC key in PEM format. The key content in the example body is the same as in the file jwkES384key2.pem
* Upload JWK - Uploads an EC key in JWK format.
* Delete JWK key - Deletes the key with the key ID (kid) specified in ``Upload JWK``
* Delete PEM key - Deletes the key with the key ID (kid) specified in ``Upload PEM key``
* List keys - Returns a JSON list of all public keys in the keystore
* Get token - Creates a JWT, signed with one of the EC keys, containing the subject (sub) passed as argument. Variables ``token``, ``kid`` and ``sub`` are set as environment variables and are used by ``Get key by ID`` and ``Verify token``.
* Get key by ID - Returns a key from the keystore identified by the key ID (kid) stored in the ``kid`` environment variable
* Verify token - Validates the JWT supplied in the ``token`` environment variable

## Using OpenSSL to generate keys

### Generate private key

Open a terminal window and type:

``openssl ecparam -name secp384r1 -genkey -noout -out jwkES384key.pem``

This will generate a new ECDSA key using P-384 and SHA-384 and store it in the file ``jwkES384key.pem``

### Generate public key

First generate a private key as described in the last section, next open a terminal window and type:

``openssl ec -in jwkES384key.pem -pubout -out jwkES384pubkey.pem``

This will create the public part of the key and store it in the file ``jwkES384key.pem``
