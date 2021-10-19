/*
 * @license
 * Copyright 2019 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fido2 = require('@simplewebauthn/server');
const base64url = require('base64url');
const fs = require('fs');
const low = require('lowdb');

/// Create DB root if doesn't exist
if (!fs.existsSync('./.data')) {
  fs.mkdirSync('./.data');
}
/// Get or start DB
const FileSync = require('lowdb/adapters/FileSync');
const adapter = new FileSync('.data/db.json');
const db = low(adapter);

/// Use JSON on reponses
router.use(express.json());

const RP_NAME = 'Elton Pastilha FIDO'; // Name of the server to show on FIDO2
const TIMEOUT = 30 * 1000 * 60; // Time to sign the challenge FIDO2

// Inicialite DB
db.defaults({
  users: [],
}).write();


const csrfCheck = (req, res, next) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    res.status(400).json({ error: 'invalid access.' });
    return;
  }
  next();
};

function sessionCheck(req, res, next){
  if (!req.session['signed-in']) {
    res.status(401).json({ error: 'not signed in.' });
    return;
  }
  next();
}

// Get origin to compare with do cliente
const getOrigin = (userAgent) => {
  let origin = '';
  if (userAgent.indexOf('okhttp') === 0) {
    const octArray = process.env.ANDROID_SHA256HASH.split(':').map((h) =>
      parseInt(h, 16),
    );
    const androidHash = base64url.encode(octArray);
    origin = `android:apk-key-hash:${androidHash}`;
  } else {
    origin = process.env.ORIGIN;
  }
  return origin;
}

/// Ask and receiving the challenge
router.post('/registerNewUserRequest', (req, res) => {
  const username = req.body.username;
  const userid = base64url.encode(crypto.randomBytes(32));
  const authenticatorSelection = req.body.authenticatorSelection;
  
  if (!username || !/[a-zA-Z0-9-_]+/.test(username)) {
    res.status(400).send({ error: 'Bad request' });
    return;
  } else {
    // See if account already exists
    let user = db.get('users').find({ username: username }).value();
    if(user != null) {
      res.status(409).send({ error: 'Already exist!' });
      return;
    }
    try {
      const as = {}; // authenticatorSelection
      const aa = req.body.authenticatorSelection.authenticatorAttachment;
      const rr = req.body.authenticatorSelection.requireResidentKey;
      const uv = req.body.authenticatorSelection.userVerification;
      const cp = req.body.attestation; // attestationConveyancePreference
      let asFlag = false;
      let authenticatorSelection;
      let attestation = 'none';

      if (aa && (aa == 'platform' || aa == 'cross-platform')) {
        asFlag = true;
        as.authenticatorAttachment = aa;
      }
      if (rr && typeof rr == 'boolean') {
        asFlag = true;
        as.requireResidentKey = false;
      }
      if (uv && (uv == 'required' || uv == 'preferred' || uv == 'discouraged')) {
        asFlag = true;
        as.userVerification = uv;
      }
      if (asFlag) {
        authenticatorSelection = as;
      }
      if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
        attestation = cp;
      }

      // Start the process to build the challenge and the options to send back
      const options = fido2.generateAttestationOptions({
        rpName: RP_NAME,
        rpID: process.env.HOSTNAME,
        userID: userid,
        userName: username,
        displayName: username,
        timeout: TIMEOUT,
        attestationType: attestation,
        excludeCredentials: [],
        authenticatorSelection,
      });
      
      // Save the challenge on cookies
      req.session.challenge = options.challenge;

      // Temporary hack until SimpleWebAuthn supports `pubKeyCredParams`
      options.pubKeyCredParams = [];
      const params = [-7,-257];
      for (let param of params) {
        options.pubKeyCredParams.push({ type: 'public-key', alg: param });
      }
      /// Send it back
      res.json(options);
    } catch (e) {
      res.status(400).send({ error: e });
    }
  }
  
});

/// Receive and confirming the challenge signatue and the new user
router.post('/registerNewUserResponse', csrfCheck, async (req, res) => {
  const username = req.body.username;
  const userid = base64url.decode(req.body.userid);
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;
  const credId = req.body.id;
  const type = req.body.type;

  try {
    const { body } = req;
    /// Start the FIDO2 Server verification process
    const verification = await fido2.verifyAttestationResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
    });

    const { verified, authenticatorInfo } = verification;
    /// Check if challenge signature is ok or any other data
    if (!verified) {
      throw 'User verification failed.';
    }

    const { base64PublicKey, base64CredentialID, counter } = authenticatorInfo;

    ///Create new User
   const user = {
        username: username,
        id: req.body.userid,
        credentials: [],
      };

    const existingCred = user.credentials.find(
      (cred) => cred.credID === base64CredentialID,
    );

    if (!existingCred) {
      /// Add credential to the new User
      user.credentials.push({
        publicKey: base64PublicKey,
        transports: (body.transports=='platform'?['internal']:['usb', 'ble', 'nfc']),
        credId: base64CredentialID,
        prevCounter: counter,
      });
    }
    
    /// Save user in DB
    db.get('users').push(user).write();

    req.session.username = user.username;
    delete req.session.challenge;

    // Respond with user info
    res.json(user);
  } catch (e) {
    delete req.session.challenge;
    res.status(400).send({ error: e.message });
  }
});


/// Ask and receiving the challenge
router.post('/signinUserRequest', csrfCheck, async (req, res) => {
  try {
  // Get user from DB
    const user = db
      .get('users')
      .find({ username: req.body.username })
      .value();

    if (!user) {
      // Send empty response if user is not registered yet.
      res.json({ error: 'User not found.' });
      return;
    }
    // Get credential already registed
    const allowCredentials = [];
     for (let cred of user.credentials) {
        allowCredentials.push({
          id: cred.credId,
          type: 'public-key',
          transports: cred.transports
        });
    }
    user.credentials;

    // Start the process to build the challenge and the options to send back
    const options = fido2.generateAssertionOptions({
      timeout: TIMEOUT,
      rpID: process.env.HOSTNAME,
      allowCredentials,
      userVerification: "discouraged",
    });
    req.session.challenge = options.challenge;
    options.user = {};
    options.user.id = user.id;
    options.user.username = user.username;
    
    // Respond with challenge
    res.json(options);
  } catch (e) {
    delete req.session.challenge;
    res.status(400).json({ error: e });
  }
});

/// Receive and confirming the challenge signatue
router.post('/signinUserResponse', csrfCheck, async (req, res) => {
  const { body } = req;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;

  // Get user from DB
  const user = db.get('users').find({ username: body.username }).value();

  let credential = user.credentials.find((cred) => cred.credId === req.body.id);

  try {
    if (!credential) {
      throw 'Authenticating credential not found.';
    }

    /// Start the FIDO2 Server verification process
    const verification = fido2.verifyAssertionResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator: credential,
    });

    const { verified, authenticatorInfo } = verification;

    if (!verified) {
      throw 'User verification failed.';
    }

    // Update the counter
    credential.prevCounter = authenticatorInfo.counter;

    /// Save the changes
    db.get('users').find({ id: body.userid }).assign(user).write();

    delete req.session.challenge;
    req.session.username = user.username;
    req.session['signed-in'] = 'yes';
    ///Send the sign-in complete
    res.status(200).json(user);
  } catch (e) {
    delete req.session.challenge;
    res.status(400).json({ error: e });
  }
});


router.get('/signout', (req, res) => {
  delete req.session['signed-in'];
  res.redirect(302, '/');
});

/// Get the keys from the current user
router.post('/getKeys', csrfCheck, sessionCheck, (req, res) => {
  const user = db.get('users').find({ username: req.session.username }).value();
  res.json(user || {});
});

/// Remove key from the current user
router.post('/removeKey', csrfCheck, sessionCheck, (req, res) => {
  const credId = req.query.credId;
  const username = req.session.username;
  const user = db.get('users').find({ username: username }).value();

  const newCreds = user.credentials.filter((cred) => {
    // Leave credential ids that do not match
    return cred.credId !== credId;
  });

  db.get('users')
    .find({ username: username })
    .assign({ credentials: newCreds })
    .write();

  res.json({});
});

/// Clear DB for tests propose
router.get('/resetDB', (req, res) => {
  db.set('users', []).write();
  const users = db.get('users').value();
  res.json(users);
});


/// Ask and receiving the challenge
router.post('/registerRequest', csrfCheck, sessionCheck, async (req, res) => {
  const username = req.session.username;
  const user = db.get('users').find({ username: username }).value();
  try {
    const excludeCredentials = [];
    if (user.credentials.length > 0) {
      for (let cred of user.credentials) {
        excludeCredentials.push({
          id: cred.credId,
          type: 'public-key',
          transports: cred.transports,
        });
      }
    }
    const pubKeyCredParams = [];
    const params = [-7, -257];
    for (let param of params) {
      pubKeyCredParams.push({ type: 'public-key', alg: param });
    }
    const as = {}; // authenticatorSelection
    const aa = req.body.authenticatorSelection.authenticatorAttachment;
    const rr = req.body.authenticatorSelection.requireResidentKey;
    const uv = req.body.authenticatorSelection.userVerification;
    const cp = req.body.attestation; // attestationConveyancePreference
    let asFlag = false;
    let authenticatorSelection;
    let attestation = 'none';

    if (aa && (aa == 'platform' || aa == 'cross-platform')) {
      asFlag = true;
      as.authenticatorAttachment = aa;
    }
    if (rr && typeof rr == 'boolean') {
      asFlag = true;
      as.requireResidentKey = rr;
    }
    if (uv && (uv == 'required' || uv == 'preferred' || uv == 'discouraged')) {
      asFlag = true;
      as.userVerification = uv;
    }
    if (asFlag) {
      authenticatorSelection = as;
    }
    if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
      attestation = cp;
    }

    // Start the process to build the challenge and the options to send back
    const options = fido2.generateAttestationOptions({
      rpName: RP_NAME,
      rpID: process.env.HOSTNAME,
      userID: user.id,
      userName: user.username,
      timeout: TIMEOUT,
      attestationType: attestation,
      excludeCredentials,
      authenticatorSelection,
    });

      // Save the challenge on cookies
    req.session.challenge = options.challenge;

    // Temporary hack until SimpleWebAuthn supports `pubKeyCredParams`
    options.pubKeyCredParams = [];
    for (let param of params) {
      options.pubKeyCredParams.push({ type: 'public-key', alg: param });
    }

    res.json(options);
  } catch (e) {
    res.status(400).send({ error: e });
  }
});

/// Receive and confirming the challenge signatue and the new credential
router.post('/registerResponse', csrfCheck, sessionCheck, async (req, res) => {
  const username = req.session.username;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;
  const credId = req.body.id;
  const type = req.body.type;

  try {
    const { body } = req;

    /// Start the FIDO2 Server verification process
    const verification = await fido2.verifyAttestationResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
    });

    const { verified, authenticatorInfo } = verification;

    if (!verified) {
      throw 'User verification failed.';
    }

    const { base64PublicKey, base64CredentialID, counter } = authenticatorInfo;

    /// Get the current user
    const user = db.get('users').find({ username: username }).value();

    const existingCred = user.credentials.find(
      (cred) => cred.credID === base64CredentialID,
    );

    if (!existingCred) {
      /// add the key to the user
      user.credentials.push({
        publicKey: base64PublicKey,
        transports: (body.transports=='platform'?['internal']:['usb', 'ble', 'nfc']),
        credId: base64CredentialID,
        prevCounter: counter,
      });
    }
    /// Save the key
    db.get('users').find({ username: username }).assign(user).write();

    delete req.session.challenge;

    // Respond with user info
    res.json(user);
  } catch (e) {
    delete req.session.challenge;
    res.status(400).send({ error: e.message });
  }
});

module.exports = router;
