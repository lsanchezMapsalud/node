const express = require('express')
const app = express();
const bodyParser = require('body-parser')

const port = 3000
const { google } = require('googleapis');
const fs = require('fs');
const crypto = require('crypto');


let jsonParser = bodyParser.json()

app.post('/api/decode_token',jsonParser, (req, res) => {


  //return res.send(req.body.tk)

  async function validateToken() {
  
    let jsonData = fs.readFileSync('app.json');
    let credent = JSON.parse(jsonData);


    const auth = new google.auth.GoogleAuth({
      credentials: credent, // Replace with your credentials
      scopes: ['https://www.googleapis.com/auth/playintegrity'],
    });
    const authClient = await auth.getClient();
    google.options({ auth: authClient });


    google.options({ auth: authClient });

    //const api = google.playintegrity({ version: "v1" });



    const response = await google.playintegrity('v1').v1.decodeIntegrityToken({

      packageName: "com.liderdigital.lapositiva.app",
      requestBody: {
        integrityToken: req.body.tk,
      },
    });

    let dataResponse = response.data.tokenPayloadExternal;

    if(dataResponse.accountDetails.appLicensingVerdict=='UNLICENSED'){

      return res.send({"data": { "validate": 2,"response":"El usuario no tiene derechos de acceso a la app. Esto sucede, por ejemplo, cuando el usuario transfiere tu app desde una fuente desconocida o no la adquiere en Google Play."},"message": "Information","status":200  });

    }

    if(dataResponse.accountDetails.appLicensingVerdict=='UNEVALUATED'){

      return res.send({"data": { "validate": 3,"response":"No se evaluó la información de las licencias porque se omitió un requisito necesario."},"message": "Information","status":200  });

    }

    if(dataResponse.accountDetails.appLicensingVerdict=='LICENSED'){
      
      let deviceIntegrity=dataResponse.accountDetails.deviceIntegrity;
      if(deviceIntegrity!='{}'){
        if(dataResponse.deviceIntegrity.deviceRecognitionVerdict){

          let deviceRecognitionVerdict =dataResponse.deviceIntegrity.deviceRecognitionVerdict;

          let countVeredict=0;
          deviceRecognitionVerdict.forEach(function(item) {
            countVeredict ++;
          });

          if(countVeredict>=1){
            return res.send({"data": { "validate": 1,"response":"dispositivo cumple con los criterios"},"message": "Information","status":200  });

          }
        }else{
          return res.send({"data": { "validate": 5,"response":"La app se está ejecutando en un dispositivo que muestra indicios de ataque (como trampas de API) o de vulneración del sistema (como un dispositivo con permisos de administrador), o bien no se está ejecutando en un dispositivo físico (como un emulador que no pasa las verificaciones de Google Play Integrity)."},"message": "Information","status":200  });

        }
      }else{

        return res.send({"data": { "validate": 4,"response":"dispositivo no cumple con los criterios"},"message": "Information","status":200  });

      }


    }


 
    //return res.send(response.data);

  }

  validateToken();

  
})

app.post('/api/generate_nonce',jsonParser,(req, res) =>{

  const generateNonce = () => {
    // Crear un string seguro para URL
    const urlSafeString = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.';

    // Generar una cadena aleatoria con los caracteres permitidos (longitud máxima de 500)
    let nonce = '';
    const maxLength = 500;
    for (let i = 0; i < maxLength; i++) {
        nonce += urlSafeString.charAt(Math.floor(Math.random() * urlSafeString.length));
    }

    // Codificar la cadena en Base64
    const base64Nonce = Buffer.from(nonce).toString('base64');

    // Asegurarse de que el nonce esté entre 16 y 500 caracteres
    const minNonceLength = 16;
    const maxNonceLength = 500;
    const trimmedNonce = base64Nonce.slice(0, Math.floor(Math.random() * (maxNonceLength - minNonceLength + 1)) + minNonceLength);

    return trimmedNonce;
  };

  const generatedNonce = generateNonce();

  return res.send({"data": { "nonce": generatedNonce},"message": "Information","status":200  });


})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})