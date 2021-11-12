/**
 * Nome: Bianca Camargo Machado
 * Trabalho 3 de Segurança de Sistemas - Simular parte do HTTPS
 * 30/06/2021
 * Mensagens trocadas:
 * 
 *  Enviadas:
 *   A = 9e98be7a4b690193d21ceb287ec97d9ebbbc4734073164cfc03c7a04411f4730400ecea8112391b6c42915f5fbf2d0e18c8f9a67cc91814af4e6aadb2d3e2aaf3308968b7b2fef3494d31dc6b991a8069f691426a49937ba576e906fed9422cf0d08cd8f1c19d234aea238b097023f3a5f7f4ecfae2ade0d2cda6422ed15a0f
 *   MSG invertida cifrada = 8634643900f08755f64b2fa2c4709d03b5cf6aea5b646522c224e336aadc664b21bffe5d39a3e8ec0a233b93add602537d121971fa0b840f16c6673d79eed3e5dc6335e96d7626026696dedb44c189c199c8da2320ae9e2ca3076726af1226127c3e4453500ab88c5a9707becb1547b0
 * 
 *  Recebidas:
 *   B = 5A0B1B5D5794404EADAE3BE9D3F72AF602FDB4F066C7B9AD39632FD581CDB4646759F25183209404D1241567F7F873F1A01FA40F33F285CF10375E923FD8C0A53FCB9C98058A5E0DF665C9D5A86058659C51F1CE7C4D68D1389110B9D7CD74DE0A2AB158F373A99F61923B6103AAA55966698417E38F5CE3B16B25404CEDCF10
 *   MSG = 580D66D68E6DF45E969CCAB880925DDE4C2D4E5706B38B38DA434035FE9A18BC53BD34964B094CA7C66CAC2B80FB8FF93A3BC8613261E660F9148B61F3A33EB893B3994E2EDC34EC1135CDBE108803B155CEA5662B97714089CCD9A9F4DC21E2
 *   MSG decifrada = Show Bianca. Agora inverte esta frase, cifra ela e manda ela de volta cifrada
 *   MSG de confirmação = C98C684B7239B854F341D5CD20912A31E4C23362E2BBFDCCBA7164FD8CF4AB68F8B97D0DB35CF0561785E08CD898EF6250CE48ADEEF358AC02070C4C31F04C456F2E37B45A3A202989CCF14256B6C653869E4A620CDF5B298F56EBC062EFF3D5AE7FA182AF3DC9BBF13C3D7755D8B1A4CCC853A49C323A7CB17C4AA29D7678800965CD2EA08620BD7154916F9DFEA4C0
 *   MSG de confirmação decifrada = Legal. Agora está ok. Manda o código comentado com este exemplo completo no início do código e submete no Moodle. Valeu
 * 
 * Como executar:
 * - Requisitos: NodeJS v12+
 * - Altere o valor das variáveis de entrada, se necessário (linhas 97-107)
 * - Execute `node index.js`
 */
const crypto = require('crypto');

// Converte para Uint8Array
const fromHexString = (hexString) =>
  new Uint8Array(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

const getHash = (hexString) => {
  const value = Buffer.from(fromHexString(hexString));
  // Calcula o hash de determinado conjunto de bytes
  const hash = crypto.createHash('sha256').update(value);

  // Retorna o hash calculado
  return hash;
};

const getV = (B, a, p) => {
  // converte de hexa para BigInt
  const BigIntB = BigInt(`0x${B}`);
  const V = String(BigIntB ** a % p); // V = Ba mod p

  return V;
};

/**
 * Decifra mensagem a partir do texto e chava em hexa
 * Retorna mensagem decifrada
 */
const decrypt = (message, hexKey) => {
  const key = Buffer.alloc(16, hexKey, 'hex');

  const complete = Buffer.from(message, 'hex');

  const encoded = Buffer.alloc(
    complete.length,
    message.slice(32, message.length),
    'hex'
  );

  var iv = Buffer.from(message.slice(0, 32), 'hex');

  console.log('iv ===> ', message.slice(0, 32), '\n');
  var decoded = encoded;
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  let decrypted = decipher.update(decoded);
  decrypted += decipher;
  return decrypted;
};

/**
 * Cifra mensagem a partir de texto claro e a chave em hexa
 */
const encrypt = (plainText, hexKey) => {
  const textBuffer = Buffer.from(plainText);
  const key = Buffer.from(hexKey, 'hex');

  //aqui ta gerando o iv aleatorio
  crypto.randomFill(new Uint8Array(16), (err, iv) => {
    if (err) throw err;

    var encoded = Buffer.concat([iv, textBuffer]);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    let encrypted = cipher.update(encoded, 'binary', 'hex');
    const hexIV = Buffer.from(iv).toString('hex');

    encrypted += cipher.final('hex');
    console.log(
      '\nMensagem invertida cifrada: ',
      (hexIV + encrypted).toUpperCase()
    );
  });
};

function main() {

  // Entradas
  const hexP =
    'B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371';
  const hexG =
    'A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5';

  // recebido após o envio de A
  const B =
    '5A0B1B5D5794404EADAE3BE9D3F72AF602FDB4F066C7B9AD39632FD581CDB4646759F25183209404D1241567F7F873F1A01FA40F33F285CF10375E923FD8C0A53FCB9C98058A5E0DF665C9D5A86058659C51F1CE7C4D68D1389110B9D7CD74DE0A2AB158F373A99F61923B6103AAA55966698417E38F5CE3B16B25404CEDCF10';
  // mensagem a ser defifrada, em hexa
  const MSG =
    '580D66D68E6DF45E969CCAB880925DDE4C2D4E5706B38B38DA434035FE9A18BC53BD34964B094CA7C66CAC2B80FB8FF93A3BC8613261E660F9148B61F3A33EB893B3994E2EDC34EC1135CDBE108803B155CEA5662B97714089CCD9A9F4DC21E2';
  
  // Converte os valores para BigInt
  const a = BigInt(102); // a < p
  const p = BigInt(`0x${hexP}`);
  const g = BigInt(`0x${hexG}`);

  const decA = String(g ** a % p);

  console.log('A (hex) ==>', BigInt(decA).toString(16));

  // Passo 2: receber um valor B (em hexadecimal) do professor e calcular V = Ba mod p
  const V = getV(B, a, p);
  console.log('V ==> ', V);
  const hexV = BigInt(V).toString(16);
  console.log('V (hex) ==> ', hexV);

  const S = getHash(hexV).digest('hex');
  console.log('S ==> ', S);

  // usar os primeiros 128 bits como senha para se comunicar com o professor
  const key = S.slice(0, 32);
  console.log('Password: ', key);

  // decifrando mensagem
  const result = decrypt(MSG, key);

  const final = result.slice(0, result.length - 18);
  console.log(final);

  const reverse = final.split('').reverse().join('');
  encrypt(reverse, key);

  console.log('Mensagem invertida: ', reverse);
}

main();
