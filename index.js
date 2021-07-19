require('dotenv').config()
const express = require('express')
var exphbs  = require('express-handlebars');
const session = require('express-session')
const axios = require('axios')
var OktaAuth = require('@okta/okta-auth-js').OktaAuth;

var config = {
    issuer: process.env.ORG_URI+'/oauth2/default',
    clientId: process.env.CLIENT_ID,
    redirectUri: process.env.CALLBACK,
  };
  
var authClient = new OktaAuth(config);



var app = express();
app.engine('handlebars', exphbs());
app.set('view engine', 'handlebars');
app.use('/static', express.static('static'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {secure: false}
}));  

app.get('/', function (req, res) {
    res.render('home');
});

app.post('/login', function (req, res) {

    axios.post(process.env.ORG_URI+"/api/v1/authn",{username:req.body.username,password: req.body.password, options:{multiOptionalFactorEnroll: true,}})
      .then(function(transaction) {
        if (transaction.data.status === 'SUCCESS') {
          res.session.sessionToken = transaction.data.sessionToken
          res.redirect('/profile')
        } else if (transaction.data.status === 'MFA_REQUIRED') {
          var webauthn = transaction.data._embedded.factors.filter(ele => ele.factorType == "webauthn")
          if(webauthn.length>0){
              console.log(webauthn)
              var authid = webauthn[0].profile.credentialId
              axios.post(webauthn[0]._links.verify.href,{stateToken: transaction.data.stateToken})
              .then(function(verify) {
                req.session.next = verify.data._links.next.href
                console.log(verify.data._embedded.factor._embedded.challenge)
                res.render('webauthn',
                {
                  stateToken: verify.data.stateToken,
                  challenge: JSON.stringify(verify.data._embedded.factor._embedded.challenge),
                  authid: authid
                })
              })
              .catch(function(err) {
                console.error(err);
                res.render('home',{error:JSON.stringify(err)});
              });

          }
          else if(transaction.factors.filter(ele => ele.factorType == "password").length>0){
            var passwordFactor = req.session.transaction.factors.find(function(factor){
              return factor.provider === 'OKTA' && factor.factorType === 'password';
            })
            passwordFactor.verify()
            .then(function (verify){
              req.session.transaction = verify
              obj = verify
              res.render('password')
            })
            .catch(function(err) {
              console.error(err);
              res.render('home',{error:JSON.stringify(err)});
            })
          }
          else {
              throw 'We cannot handle any of your factors ' + JSON.stringify(transaction.factors);
          }
        }
        else if (transaction.data.status === "MFA_ENROLL"){
          var webauthn = transaction.data._embedded.factors.filter(ele => ele.factorType == "webauthn")
          if(webauthn.length>0){
            axios.post(webauthn[0]._links.enroll.href,{stateToken: transaction.data.stateToken,factorType: "webauthn", provider: "FIDO"})
              .then(function(enroll) {
                console.log(enroll)
                req.session.next = enroll.data._links.next.href
                res.render('enroll',
                {
                  stateToken: enroll.data.stateToken,
                  activation: JSON.stringify(enroll.data._embedded.factor._embedded.activation)
                })
              })
          }
        } else {
          console.log(transaction)
          throw 'We cannot handle the ' + transaction.data.status + ' status';
        }
      })
      .catch(function(err) {
        console.error(err);
        res.render('home',{error:JSON.stringify(err)});
      });
});

app.post('/login/password', function (req, res) {
  obj.verify({password: req.body.password})
  .then(function(transaction) {
    console.log(transaction)
  })
  .catch(function(err) {
    console.error(err);
    res.render('home',{error:JSON.stringify(err)});
  })
})

app.post('/enroll/webauthn', function (req, res) {
  axios.post(req.session.next,{stateToken: req.body.state,attestation: req.body.attestationObject, clientData: req.body.clientData})
  .then(function(activation) {
    if(activation.status == 200){
      if(activation.data.status === 'MFA_ENROLL'){
        axios.post(activation.data._links.skip.href,{stateToken: activation.data.stateToken})
        .then(function(skip) {
          req.session.sessionToken = skip.data.sessionToken
          res.redirect('/profile')
        })
      } else {
        req.session.sessionToken = activation.data.sessionToken
        res.redirect('/profile')
      }
    }
    else{
      res.render('home',{error:JSON.stringify(err)});
    }
  })
  .catch(function(err) {
    console.log("c")
    console.error(err);
    res.render('home',{error:JSON.stringify(err)});
  })
})

app.post('/login/webauthn', function (req, res) {
  console.log(req.body)
  console.log(req.session)

  axios.post(req.session.next,{
    stateToken: req.body.state,
    authenticatorData: req.body.authenticatorData, 
    clientData: req.body.clientData, 
    signatureData: req.body.signatureData})
  .then(function(authn) {
    req.session.sessionToken = authn.data.sessionToken
    res.redirect('/profile')
  })
  .catch(function(err) {
    console.error(err);
    res.render('home',{error:JSON.stringify(err)});
  })
})

app.get('/profile', function (req, res) {
  res.render('profile', {sessionToken: req.session.sessionToken});
})

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('app started'));