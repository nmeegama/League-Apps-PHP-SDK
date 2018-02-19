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
define("CLIENT_ID", "103920271064430911681");
define("KEY_FILE_PATH", "103920271064430911681.p12");


///Using Jose PHP-JWt library
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
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

//echo "<pre>";
//print_r($cert_info);
//echo "</pre><hr>";

// End reading the private key.


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


//echo "<pre>";
//print $jose_token;
//echo "</pre><hr>";

$post_data = [
  'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
  'assertion' => $jose_token,
];


////GUZZLE PHP lib////

/// Admin Authentication///
$client = new Client([
  // Base URI is used with relative requests
  'base_uri' => AUTH_HOST,
]);
$response = $client->request('POST', '', [
  'query' => $post_data
]);
$body = $response->getBody();
$code = $response->getStatusCode();
//echo "<pre>";
//print  $code;
//echo "</pre><hr>";


$response_data = json_decode($body->getContents());
$access_token = $response_data->access_token;

//echo "<pre>";
//print_r($access_token);
//echo "</pre><hr>";

/// END Admin Authentication///


// Accessing Admin API ///

$admin_client = new Client([
  // Base URI is used with relative requests
  'base_uri' => API_HOST,
  'headers' => ['authorization' => 'Bearer '.$access_token]
]);

$registrations = $admin_client->request('GET', '/v2/sites/8027/export/registrations?debug-json', [
  'query' => ['last-updated' => '1451485586']
]);


echo "<pre>";
print_r($registrations->getBody()->getContents());
echo "</pre><hr>";
// END Accessing Admin API ///

////END GUZZLE////


