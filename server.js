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

// init project
const express = require('express');
const session = require('express-session');
const hbs = require('hbs');
const auth = require('./api/auth');
const app = express();

app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.set('views', './views');
app.use(express.json());
app.use(express.static('public'));
app.use(express.static('dist'));
app.use(session({
  secret: process.env.SESSION_SECRET, 
  //name : process.env.SESSION_NAME,
  resave: true,
  saveUninitialized: false,
  proxy: true,
  cookie:{
    httpOnly: true,
    secure: true,
    sameSite: 'none'
  }
}));

//define hostname for rpID fild on FIDO2
app.use((req, res, next) => {
  if (process.env.PROJECT_DOMAIN) {
    process.env.HOSTNAME = `${process.env.PROJECT_DOMAIN}.glitch.me`;
  } else {
    process.env.HOSTNAME = req.headers.host;
  }
  req.schema = 'https';
  next();
});


app.get('/', (req, res) => {
  // Check session
  console.log(req.session);
  if (req.session.username && req.session['signed-in'] == 'yes') {
    // If user is signed in, redirect to `/reauth`.
    res.redirect(307, '/home');
    return;
  }
  // If user is not signed in, show `index.html`.
  res.render('index.html');
});

app.get('/register', (req, res) => {
  if (req.session.username && req.session['signed-in'] == 'yes') {
    // If user is not signed in, redirect to `/`.
    res.redirect(307, '/home');
    return;
  }
  // `register.html` shows register form to register new user
  res.render('register.html');
});

app.get('/login', (req, res) => {
  if (req.session.username && req.session['signed-in'] == 'yes') {
    // If user is not signed in, redirect to `/`.
    res.redirect(307, '/home');
    return;
  }
  // `login.html` shows sign-in form
  res.render('login.html');
});

app.get('/home', (req, res) => {
  if (!req.session.username || req.session['signed-in'] != 'yes') {
    // If user is not signed in, redirect to `/`.
    res.redirect(307, '/');
    return;
  }
  // `home.html` shows home page with the links for login and register
  res.render('home.html', { username: req.session.username });
});

// Build the assetLinks for Android and from .env file, and redirect from /.well-known/assetlinks.json
app.get('/.well-known/assetlinks.json', (req, res) => {
  const assetlinks = [];
  const relation = [
    'delegate_permission/common.handle_all_urls',
    'delegate_permission/common.get_login_creds',
  ];
  assetlinks.push({
    relation: relation,
    target: {
      namespace: 'web',
      site: process.env.ORIGIN,
    },
  });
  if (process.env.ANDROID_PACKAGENAME && process.env.ANDROID_SHA256HASH) {
    assetlinks.push({
      relation: relation,
      target: {
        namespace: 'android_app',
        package_name: process.env.ANDROID_PACKAGENAME,
        md5_cert_fingerprints: [process.env.ANDROID_MD5HASH],
        sha1_cert_fingerprints: [process.env.ANDROID_SHA1HASH],
        sha256_cert_fingerprints: [process.env.ANDROID_SHA256HASH],
      },
    });
  }
  res.json(assetlinks);
});

// all routes to /api/auth go to the file api/auth.js
app.use('/api/auth', auth);

// listen for req :)
const port = process.env.GLITCH_DEBUGGER ? null : 8080;
const listener = app.listen(port || process.env.PORT, () => {
  console.log('Your app is listening on port ' + listener.address().port);
});
