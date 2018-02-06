<?php
/**
 * Created by PhpStorm.
 * User: nmeegama
 * Date: 6/02/18
 * Time: 2:55 AM
 */
require 'vendor/autoload.php';
define("AUTH_HOST", 'https://auth.leagueapps.io/v2/auth/token');
define("API_HOST", 'https://admin.leagueapps.io');
define("CLIENT_ID", "govavi");
define("KEY_FILE_PATH", "103920271064430911681.p12");

//U sing the Fire bas JWT lib : https://github.com/firebase/php-jwt.
use \Firebase\JWT\JWT;
use Lcobucci\JWT\Builder;

// Using the Lcobucci PHP lib : https://github.com/lcobucci/jwt
use Lcobucci\JWT\Signer\Keychain; // just to make our life simpler
use Lcobucci\JWT\Signer\Rsa\Sha256; // you can use Lcobucci\JWT\Signer\Ecdsa\Sha256 if you're using ECDSA keys



///Using Jose PHP-JWt library
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;


// HTTP client.
use \GuzzleHttp\Client;

// Reading the Private key.

if (!$key = file_get_contents(KEY_FILE_PATH)) {
  echo "Error: Unable to read the cert file\n";
  exit;
}
if (!openssl_pkcs12_read($key, $cert_info, "notasecret")) {
  echo "Error: Unable to read the cert store.\n";
  exit;
}
$private_key = $cert_info['pkey'];

echo "<pre>";
print_r($cert_info);
echo "</pre><hr>";

// End reading the private key.



// FIREBASE

$data = array(
  'aud'=> AUTH_HOST,
  'iss'=> CLIENT_ID,
  'sub'=> CLIENT_ID,
  'iat'=> time(),
  'exp'=> time() + 300
);
$jwt = JWT::encode($data, $private_key, 'RS256');


//END FIREBASE


/// Lcobucci

$signer = new Sha256();
$keychain = new Keychain();
$token = (new Builder())->setIssuer(CLIENT_ID)// Configures the issuer (iss claim)
  ->setAudience(AUTH_HOST)// Configures the audience (aud claim)
  ->setSubject(CLIENT_ID)
  ->setIssuedAt(time())
  ->setExpiration(time() + 300)// Configures the expiration time of the token (exp claim)
  ->sign($signer, $keychain->getPrivateKey($private_key))
  ->getToken(); // Retrieves the generated token

echo "<pre>";
print $token;
echo "</pre><hr>";


// END Lcobucci


//// Jose

$algorithmManager = AlgorithmManager::create([
  new RS256(),
]);

$jsonConverter = new StandardConverter();
$jwsBuilder = new JWSBuilder(
  $jsonConverter,
  $algorithmManager
);

$payload = $jsonConverter->encode([
  'iat' => time(),
  'nbf' => time(),
  'exp' => time() + 300,
  'iss' => CLIENT_ID,
  'sub' => CLIENT_ID,
  'aud' => AUTH_HOST
]);

$key = JWKFactory::createFromPKCS12CertificateFile(
  KEY_FILE_PATH, // The filename
  'notasecret'
);

$jws = $jwsBuilder
  ->create()                               // We want to create a new JWS
  ->withPayload($payload)                  // We set the payload
  ->addSignature($key, ['alg' => 'RS256']) // We add a signature with a simple protected header
  ->build();


$serializer = new CompactSerializer($jsonConverter); // The serializer

$jose_token = $serializer->serialize($jws, 0);


echo "<pre>";
print $jose_token;
echo "</pre><hr>";


$post_data = [
  'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
  'assertion' => $jose_token,
];

$data_string = json_encode($post_data);
echo "<pre>";
echo $data_string;
echo "</pre><hr>";


/// RAW PHP CURL HTTP REQUEST//////

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, AUTH_HOST);
curl_setopt($ch, CURLOPT_POST, TRUE);
curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);

// Also used like this
/**
 curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'Content-Type: application/json',
    'Content-Length: ' . strlen($data_string))
  );
 */


// receive server response ...
curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);

$server_output = curl_exec($ch);

echo "<pre>";
print_r($server_output);
print_r($http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE));
echo "</pre><hr>";

curl_close($ch);

/// RAW PHP CURL //////




////GUZZLE PHP lib////
$client = new Client([
  // Base URI is used with relative requests
  'base_uri' => AUTH_HOST,
]);
$response = $client->request('POST', '', $post_data);

$code = $response->getStatusCode();
echo "<pre>";
print  $code;
echo "</pre><hr>";

////END GUZZLE////

