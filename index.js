const fs = require('fs')
const express = require('express');
const bodyParser = require('body-parser')
const port = 3000;
const jose = require('jose');
const http = require('http');
const {
    JWK,   // JSON Web Key (JWK)
    JWKS,  // JSON Web Key Set (JWKS)
    JWT,   // JSON Web Token (JWT)
} = jose

const keysfile = 'keystore';
const app = express();
app.use(express.static('public'));

// Load keystore
const ks = createOrLoadKeystore(keysfile);
console.log(ks)

function createOrLoadKeystore(filename) {
    try {
        let ks = loadKeystore(filename);
        console.log("Keystore loaded")
        return ks;
    } catch (error) {
        console.log(error);
        console.log("Creating new keystore");
        let ks = new JWKS.KeyStore();
        saveKeystore(filename, ks);
        return ks;
    }
}

function loadKeystore(filename) {
    return JWKS.asKeyStore(JSON.parse(fs.readFileSync(filename, 'utf8')))
}

function saveKeystore(filename, keystore) {
    fs.writeFileSync(filename, JSON.stringify(keystore.toJWKS(true)));
}

function generateECKey() {
    return JWK.generateSync('EC', 'P-384', { use: 'sig', alg: 'ES384' });
}

function getPublicKeyComponent(privKey) {
    return privKey.toJWK();
}


/*
 * Endpoint: Generate a new Elliptic Curve keypair using the P-384 curve
 */
app.get('/genkey/', (req, res) => {
    let key = generateECKey();
    res.json(key.toJWK(true));
});

/*
 * Endpoint: List all keys in JWKS (JSON Web Key Set) format. Only the public key parts are returned.
 */
app.get('/keystore/', (req, res) => {
    res.json(ks.toJWKS(false))  // false = no private keys 
});

/*
 * Endpoint: Return the public key identified by its Key ID (kid) in JWK format.
 */

app.get('/keystore/:kid', (req, res) => {
    // Returns key identified by kid
    res.json(ks.get({ kid: req.params.kid }));
});

/*
 * Endpoint: Remove the key identified by its Key ID (kid) from the JWKS keystore
 */
app.delete('/keystore/:kid', (req, res) => {
    let kid = req.params.kid;
    if (ks.get({ kid: kid })) {
        console.log(kid)
        ks.remove(ks.get({ kid: kid }))
        saveKeystore(keysfile, ks);
        res.send();
    }
    res.status(404);
    res.send()
});


/*
 * Endpoint: Upload a key to the keystore, either in JWK or PEM format. If the first character in the
 * body is "{", a JSON object (JWK format) is assumed, otherwise PEM format is assumed
 */
app.post('/keystore/', bodyParser.text({ type: '*/*' }), (req, res) => {
    // Add key to keystore
    console.log(req.body);
    let raw = req.body
    if (raw.startsWith('{')) {
        try {
            raw = JSON.parse(raw);
        }
        catch (error) {
            console.log("Not a JSON object");
        }
    }
    let key = JWK.asKey(raw, { alg: 'ES384', use: 'sig' });
    if (ks.get({ kid: key.kid })) {
        console.log(key.kid)
        ks.remove(ks.get({ kid: key.kid }))
    }
    ks.add(key);
    saveKeystore(keysfile, ks);
    res.json(getPublicKeyComponent(key));
});

/*
 * Endpoint: Get a JWT (JSON Web Token) with the passed subject, using a matching key in the
 * keystore to compute the EC signature
 */
app.get('/token/:sub', (req, res) => {
    let key = ks.get({ kty: 'EC', crv: 'P-384' });
    let payload = {
        sub: req.params.sub,
    }

    let token = JWT.sign(payload, key, {
        issuer: 'https://keys.example.com',
        expiresIn: '2 min',
        header: {
            typ: 'JWT'
        }
    })
    res.type('text/plain');
    res.send(token);
});

/*
 * Endpoint: Decodes the supplied token without doing any validation
 */
app.get('/token/decode/:token', (req, res) => {
    let token = req.params.token;
    console.log("Token to decode", token);
    res.json(JWT.decode(token, { complete: true }));
});

/*
 * Endpoint: Validates the supplied token
 */
app.get('/token/validate/:token', (req, res) => {
    let token = req.params.token;
    console.log("Token to decode", token);
    try {
        const ver = JWT.verify(token, ks, {
            algorithms: ['ES384'],
            issuer: 'https://keys.example.com',
            clockTolerance: '1 min'
        })
        res.json(ver);
    } catch (error) {
        console.log(error)
        res.send(error);
    }


});


/**
 * 
 * This would normally be in a separate web application, but for demo purposes it's 
 * included here.
 * 
 */
app.get('/embedded_app/:token', (req, res) => {
    let token = req.params.token;
    token_decoded = JWT.decode(token, { complete: true });
    console.log("Token to validate", token_decoded);
    let kid = token_decoded.header.kid;
    let pubkey_url = 'http://localhost:3000/keystore/' + kid
    http.get(pubkey_url, (response) => {
        let chunks_of_data = [];

        response.on('data', (fragments) => {
            chunks_of_data.push(fragments);
        });

        response.on('end', () => {
            let response_body = Buffer.concat(chunks_of_data);

            // response body
            console.log("Public key from key server:", response_body.toString());
            let key = JWK.asKey(JSON.parse(response_body));
            try {
                const ver = JWT.verify(token, key, {
                    algorithms: ['ES384'],
                    issuer: 'https://keys.example.com',
                    clockTolerance: '1 min'
                })
                console.log("Token successfully verified")
                console.log(JSON.stringify(ver))
                res.send("<h1>Authorized</h1><h2>Subject: " + ver.sub + "</h2>")
            } catch (error) {
                console.log(error)
                res.status(403)
                res.send("<h1>Failed to log in</h1><pre>" + error + "</pre>");
            }
        });

        response.on('error', (error) => {
            console.log(error);
        });
    })
});


app.listen(port, () => {
    console.log('Example app listening on port ' + port)
});