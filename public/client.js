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

/// Log html constructor
export const logDiv = (payload, method = "") => {
  
  var divTemporary = document.createElement("pre"); 
  divTemporary.classList.add((method == ""? "received":"send"));
  if(method != "") {
    divTemporary.innerHTML += '<p>method: "'+method+'"</p>';
  } else {
    divTemporary.innerHTML += '<p>Response</p>';
  }
  divTemporary.innerHTML += '<p>body: "'+payload+'"</p>';
  
  return divTemporary
};

/// Credentials HTML view constructor
import { html, render } from 'https://unpkg.com/lit-html@1.0.0/lit-html.js?module';
export const getCredentials = async () => {
  const res = await _fetch('/api/auth/getKeys');
  const list = document.querySelector('#list');
  const creds = html`${res.credentials.length > 0 ? res.credentials.map(cred => html`
    <div class="mdc-card credential">
      <b>Credential ID: </b><span class="mdc-typography mdc-typography--body2">${cred.credId}</span>
      <b>Credential transport: </b><span class="mdc-typography mdc-typography--body2">${cred.transports.map(name => name.toUpperCase()).join(' or ')}</span>
      <b>Public-Key: </b><pre class="public-key">${cred.publicKey}</pre>
      <div class="mdc-card__actions">
        <mwc-button id="${cred.credId}" @click="${removeCredential}" raised>Remove</mwc-button>
      </div>
    </div>`) : html`
    <p>No credentials found.</p>
    `}`;
  render(creds, list);
};

/// Remove request
export const removeCredential = async (e) => {
  try {
    await unregisterCredential(e.target.id);
    getCredentials();
  } catch (e) {
    alert(e);
  }
};

/// API Service
export const _fetch = async (path, payload = '') => {
  const headers = {
    'X-Requested-With': 'XMLHttpRequest',
  };
  if (payload && !(payload instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(payload);
  }
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: headers,
    body: payload,
  });
  if (res.status === 200) {
    // Server authentication succeeded
    return res.json();
  } else {
    // Server authentication failed
    const result = await res.json();
    throw result.error;
  }
};

/// Register new user with a new credential
export const registerNewUser = async (opts, divMessagesEnchanged) => {
  /// Request Challenge
  const options = await _fetch('/api/auth/registerNewUserRequest', opts);
  divMessagesEnchanged.appendChild(logDiv(JSON.stringify(options, undefined, 2))); // Log Html
  
  var transports = options.authenticatorSelection.authenticatorAttachment
  var userIdEncoded = options.user.id;
  options.user.id = base64url.decode(userIdEncoded);
  options.challenge = base64url.decode(options.challenge);
  if (options.excludeCredentials) {
    for (let cred of options.excludeCredentials) {
      cred.id = base64url.decode(cred.id);
    }
  }
  
  /// Start FIDO2 Cliente
  const cred = await navigator.credentials.create({
    publicKey: options,
  });
  ///Receive the credential and the challenge signature
  const credential = {};
  credential.username = options.user.name;
  credential.userid = userIdEncoded;
  credential.id = cred.id;
  credential.rawId = base64url.encode(cred.rawId);
  credential.type = cred.type;
  credential.clientExtensionResults= cred.getClientExtensionResults()
  credential.transports = transports;
  credential.transportsFrom = cred.response.getTransports();
  credential.authenticatorData = base64url.encode(cred.response.getAuthenticatorData());
  credential.publicKey = base64url.encode(cred.response.getPublicKey());
  credential.publicKeyAlgorith = cred.response.getPublicKeyAlgorithm();
  if (cred.response) {
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const utf8Decoder = new TextDecoder('utf-8');
    const decodedClientData = utf8Decoder.decode(cred.response.clientDataJSON)
    const clientDataObj = JSON.parse(decodedClientData);
    const attestationObject = base64url.encode(cred.response.attestationObject);
    //const decodedAttestationObj = cbor.decode(cred.response.attestationObject);
    credential.response = {
      clientDataJSON,
      clientDataObj,
      attestationObject,
    };
  }
  
  divMessagesEnchanged.appendChild(logDiv(JSON.stringify(credential, undefined, 2), "POST")); //Log Html
  
  /// Send the credential and the challenge signature, for complete the user registration
  return await _fetch('/api/auth/registerNewUserResponse', credential);
};
  
/// Login user, passwordless
export const loginUser = async (opts, divMessagesEnchanged) => {
  /// Request Challenge
  const options = await _fetch('/api/auth/signinUserRequest', opts);
  divMessagesEnchanged.appendChild(logDiv(JSON.stringify(options, undefined, 2)));
  
  if (options.allowCredentials.length === 0) {
    console.info('No registered credentials found.');
    return Promise.resolve(null);
  }

  
  options.challenge = base64url.decode(options.challenge);
  for (let auxCred of options.allowCredentials) {
    auxCred.id = base64url.decode(auxCred.id);
  }
  
  /// Start FIDO2 Cliente
  const cred = await navigator.credentials.get({
    publicKey: options,
  });
  
  ///Receive the challenge signature
  var existCred = false;
  for (let auxCred of options.allowCredentials) {
    if(cred.id == base64url.encode(auxCred.id)) {
      existCred = true;
    }
  }
  
  if(!existCred) {
      throw 'Authenticating credential not found.';
  }

  const credential = {};
  credential.username = options.user.username;
  credential.userid = options.user.id;
  credential.id = cred.id;
  credential.type = cred.type;
  credential.rawId = base64url.encode(cred.rawId);

  if (cred.response) {
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const authenticatorData = base64url.encode(cred.response.authenticatorData);
    const signature = base64url.encode(cred.response.signature);
    const userHandle = base64url.encode(cred.response.userHandle);
    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    };
  }
  
  
  divMessagesEnchanged.appendChild(logDiv(JSON.stringify(credential, undefined, 2), "POST")); //Log Html
  
  /// Send the challenge signature, for complete the user sign-in
  return await _fetch('/api/auth/signinUserResponse', credential);
};


/// Register new credential for the account user
export const registerCredential = async (opts) => {
  /// Request Challenge
  const options = await _fetch('/api/auth/registerRequest', opts);

  options.user.id = base64url.decode(options.user.id);
  options.challenge = base64url.decode(options.challenge);
  var transports = options.authenticatorSelection.authenticatorAttachment;

  if (options.excludeCredentials) {
    for (let cred of options.excludeCredentials) {
      cred.id = base64url.decode(cred.id);
    }
  }

  /// Start FIDO2 Cliente
  const cred = await navigator.credentials.create({
    publicKey: options,
  });
  ///Receive the credential and the challenge signature
  const credential = {};
  credential.id = cred.id;
  credential.type = cred.type;
  credential.transports = transports;
  credential.rawId = base64url.encode(cred.rawId);

  if (cred.response) {
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const attestationObject = base64url.encode(cred.response.attestationObject);
    credential.response = {
      clientDataJSON,
      attestationObject,
    };
  }
  
  /// Send the credential and the challenge signature, for complete the credential registration
  return await _fetch('/api/auth/registerResponse', credential);
};

export const unregisterCredential = async (credId) => {
  /// Delete a key from the user
  return _fetch(`/api/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};
