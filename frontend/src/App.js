import React, { useState} from 'react';
import './App.css';
import mqtt from 'mqtt';
import {useEffect} from 'react';
import 'bootstrap/dist/css/bootstrap.min.css';
import Button from 'react-bootstrap/Button';
import {Card} from 'react-bootstrap';

const elliptic = require('elliptic');
const sha3 = require('js-sha3');
var ecies = require("eciesjs");
const ec = new elliptic.ec('secp256k1');
var gateway1_pubKey = '0';
var client; //Instance to connect to broker.

/*******************UTILITY FUNCTIONS*****************/
/*
'Encrypt' function receives 2 parameters:
1. snd - An object
2. pubK - public key of the receiver

Returns the cipher string
*/
function encrypt(snd, pubK){
  //Uses receivers public key to encrypt.
  let cipher = ecies.encrypt(pubK, Buffer.from(JSON.stringify(snd)));
  let cipher_str = cipher.toString('hex');
  return cipher_str;
}

/*
'Decrypt' function receives two parameters:
1. rcv - Cipher text in the form of buffer.
2. prvK - Own private key

Returns the decrypted object
*/
function decrypt(rcv, prvK){
  //Uses own private key to decrypt.
  let cipher_str = rcv.toString();
  // console.log("Received - Encrypted message (String): ", cipher_str);
  let cipher = Buffer.from(cipher_str,'hex');
  // console.log("Received - Encrypted message (Buffer): ", cipher);
  var rcv_data = ecies.decrypt(prvK, cipher).toString();
  rcv_data = JSON.parse(rcv_data);
  return rcv_data;
}

/**
'sign_it' function
Parameters:
1. prvK - Own private key
2. Other parameters which are to be concatenated,
hashed and then signed can be accessed through 'arguments'.

Returns the signature object of the form:
{
  r:string,
  s: string,
  recover paramters: number
}
*/
function sign_it(prvK){
  let msg =  "";
  for (let i=1;i<arguments.length;i++)
    msg += arguments[i];
  let msgHash = sha3.keccak256(msg);
  let signature = ec.sign(msgHash, prvK, "hex", {canonical: true});

  //The signature below consists of parameters 'r' and 's'.
  let sign_str = JSON.parse(JSON.stringify(signature));
  return sign_str;
}

/**
'verify' function:
Parameters:
1. signature - An object same as the type returned by 'sign_it'
2. pubK - public key to be verified with.
3. Other parameters which are to be concatenated and hashed can be accessed through 'arguments'.

Return: Boolean value indicating the authentcation status.
*/
function verify(signature, pubK){
  let pubKeyObj = ec.keyFromPublic(pubK,"hex");

  let msg =  "";
  for (let i=2;i<arguments.length;i++)
    msg += arguments[i];
  let msgHash = sha3.keccak256(msg);

  let auth_status = pubKeyObj.verify(msgHash, signature);

  return auth_status;
}
/******************COMPONENT FUNCTION***********************/
function App() {

  /***************INITILIAZING STATES********************/
  //Set of keys
  const [keyPair, setKeyPair] = useState({
    pubKey: null,
    privKey: null,
    privKey_0x: null
  })

  //To check whether the keys have been generated.
  const [status, setStatus] = useState({
    gen: false, //Whether the keys have been generated.
    connected: false,
    registered: false,
    cur_time_stamp: null
  });

  useEffect(() => {
      console.log("Key pair changed: ", keyPair);
  }, [keyPair])

  /***************GENERATE KEYS HANDLER********************/
  function handleGenerate(){
    console.log("Generating key pair...");

    //Creating public and private keys for the device.
    var pair = ec.genKeyPair();
    var priv = pair.getPrivate("hex");
    var pub = ec.keyFromPrivate(priv).getPublic(true,"hex");
    var priv_0x = "0x" + priv;
    var Id = sha3.keccak256(pub+gateway1_pubKey);

    setKeyPair({
      pubKey: pub,
      privKey: priv,
      privKey_0x: priv_0x,
      devId: Id
    })

    setStatus((prev) => ({
      ...prev,
      gen: true
    }));

    alert("keys have been generated")
  }

  /***************CONNECTING AND SUBSCRIBING TO MQTT AND MAIN LOGIC FOR RECEIVING MESSAGES AND REPSONDING********************/
  function handleStart(){
    console.log("Device start button clicked...");
    client = mqtt.connect('mqtt://test.mosquitto.org:8081', {protocol: 'mqtts'});
    //CONNECT TO MQTT
    client.on('connect', () => {

      /***************SUBSCRIBE TO DEVICE-ID********************/
      client.subscribe(keyPair.devId, function (err) {
        if (!err) {
          console.log("Device started,connected to mqtt...");
          setStatus((prev) => ({
            ...prev,
            connected: true
          }))
        }
        else{
          console.log("Error starting the device...");
        }
      });

      /**********MESSAGE LISTENERS**************/
      client.on('message', (topic, rcv) => {
          if(topic !== keyPair.devId)
            return;

          var data = decrypt(rcv, keyPair.privKey_0x);
          console.log("Message received: ", data);

          /***********REGISTRATION LISTENER***********/
          if(data.remark === "register")
          {
            if(data.status)
            {
              console.log("Device has been registered..Proceed for authentication !!");
              setStatus((prev) => ({
                ...prev,
                registered: true
              }))
            }
            else
            {
              console.log("Error registering the device...");
            }
          }

          /***********NONCE LISTENER***********/
          else if(data.remark === "nonce")
          {
            if(!data.status)
            {
              console.log("Device not registered...");
              return;
            }


            //We have received the nonce.
            //1. Check whether the timestamp is new.
            //2. Check the gateway
            //3. Hash the contents and sign it
            //4. Encrypt with gateways public key and send.

            let d1 = new Date(data.time_stamp);
            let d2 = new Date(status.cur_time_stamp);

            // 1.
            if(!status.cur_time_stamp || d1.getTime() > d2.getTime())
            {
              //2.
              let pubKeyObj = ec.keyFromPublic(gateway1_pubKey,"hex");
              let msgHash = sha3.keccak256(data.time_stamp);
              console.log("Message hash: ", msgHash);
              let auth_status = pubKeyObj.verify(msgHash, data.sign);

              if(auth_status)
              {
                //3.
                let sign = sign_it(keyPair.privKey, data.nonce, "dev2:hello");
                let snd = {
                devId: keyPair.devId,
                sign: sign,
                msg: "dev2:hello"
                }
                let enc_data = encrypt(snd, gateway1_pubKey);
                client.publish('gateway1/auth', enc_data);

                //Update the timestamp state.
                setStatus({
                  ...status,
                  cur_time_stamp:data.time_stamp
                })
              }
              else
                console.log("Gateway signature verification failed...");
            }
            else
              console.log("Timestamp is old...");
          }

          /***********AUTH LISTENER***********/
          else if(data.remark === "auth")
          {
            //This is the response from the gateway after processing the request.
            //1. Check gateway.
            //2. Check status.
            let d1 = new Date(data.time_stamp);
            let d2 = new Date(status.cur_time_stamp);
            if(!status.cur_time_stamp || d1.getTime() > d2.getTime())
            {
              let pubKeyObj = ec.keyFromPublic(gateway1_pubKey,"hex");
              let msgHash = sha3.keccak256(data.time_stamp);
              let auth_status = pubKeyObj.verify(msgHash, data.sign);
              if(auth_status)
                console.log("Status received: ", data.status);
              else
                console.log("Gateway signature verification failed...");
            }
            else
              console.log("Timestamp is old...");
          }
      })
    });
  }

  /***************DEVICE REGISTRATION HANDLER********************/
  function handleRegister() {
    console.log("Requesting registration...");

    //The devID, PubKey encrypted with gateway public key is sent to the gateway on the topic register1.
    let data = {
      devId: keyPair.devId,
      pubKey: keyPair.pubKey
    }
    let cipher = ecies.encrypt(gateway1_pubKey, Buffer.from(JSON.stringify(data)));
    let cipher_str = cipher.toString('hex');
    client.publish('gateway1/register', cipher_str);
  }

  /***************DEVCE AUTHENTICATION HANDLER********************/
  function handleAuth(){
    //Here the device requests the gateway for authentication.
    //The gateway responds by sending a nonce.
    console.log("Requesting nonce for authentication...");
    let data = {
      devId: keyPair.devId,
    }

    let cipher = ecies.encrypt(gateway1_pubKey, Buffer.from(JSON.stringify(data)));
    let cipher_str = cipher.toString('hex');
    client.publish('gateway1/nonce', cipher_str);
  }

  /************************COMPONENT TO BE RENDERED*****************************/
  return (
    <div className="App">
        <div className="header">
            <h1>Simulated Edge Device</h1>
            <hr/>
        </div>

        <div className="Generate Keys">
            <Button className = "GenerateButton" disabled={status.gen} variant="primary" onClick = {handleGenerate}>
                Generate key pair
            </Button>

            {(status.gen)?
            (
              <Card style={{width:'80%', marginLeft: 'auto', marginRight: 'auto', marginDown:'10px', align: 'center'}}>
                <Card.Header>Generated key pair</Card.Header>
                <Card.Body>
                <p>Public key: <i>{keyPair.pubKey}</i></p>
                <p>Private key: <i>{keyPair.privKey}</i></p>
                </Card.Body>
              </Card>

            ) :(
              console.log("Key pair not generated...")
              )
            }
        </div>
        <br/>

        <div className="Start Device">
            <Button className = "btn"  onClick={handleStart} disabled={!status.gen}>
                Start the device
            </Button>
        </div>
        <br/>

        <div className="Register Device">
            <Button className = "btn"  onClick={handleRegister} disabled={!status.connected}>
                Register
            </Button>
        </div>
        <br/>

        <div className="Authenticate Device">
            <Button className = "btn"  onClick={handleAuth} disabled={!status.registered}>
                Authenticate
            </Button>
        </div>
    </div>
  );
}

export default App;