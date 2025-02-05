<?php
/*
 Plugin Name: phpList OIDC Plugin
 Plugin URI: https://example.com/your-plugin
 Description: Enables OpenID Connect (OIDC) authentication via a provider like Keycloak.
 Version: 1.0
 */

require_once __DIR__ . 'oidc/vendor/autoload.php';
// Ensure this file is not accessed directly.
use Jumbojett\OpenIDConnectClient;



if (!defined('PHPLISTINIT')) {
    exit;
}

// Include any required libraries here (or use Composer's autoloader)
// require_once __DIR__ . '/vendor/autoload.php';

class OidcPlugin extends phplistPlugin
{

    public $name = 'oidc';
    public $description = 'Login to phpList with oidc';
    public $version = '0.1';
    private $clientId;
    private $clientSecret;
    private $issuerUrl;
    private $redirectUri;
    private $scopes = 'openid email profile';

    public function __construct()
    {
        parent::__construct();

        $this->clientId     = getConfig('OIDC_CLIENT_ID');
        $this->clientSecret = getConfig('OIDC_CLIENT_SECRET');
        $this->issuerUrl    = getConfig('OIDC_ISSUER_URL');
        $this->redirectUri  = getConfig('OIDC_REDIRECT_URI');

    }

//    private function registerHooks() {
//        // Example: Add a button to the login page.
//        // You might have a hook similar to:
//        add_action('login_page_extra', [$this, 'displayOidcButton']);
//    }

//    public function displayOidcButton() {
//        echo '<p><a href="' . $this->getAuthorizationUrl() . '" class="btn">Login with OIDC</a></p>';
//    }

    public function login()
    {
        if (isset($_GET['oidc'])) {
            $this->handleCallback();
        } else {
            echo '<a href="' . $this->issuerUrl . '">Login with OIDC</a>';
        }
    }

    /**
     * Build the authorization URL to redirect the user to the OIDC provider.
     */
    public function getAuthorizationUrl() {
        $oidc = new OpenIDConnectClient(
            $this->issuerUrl,
            $this->clientId,
            $this->clientSecret
        );
        $oidc->setRedirectURL($this->redirectUri);
        $oidc->addScope(explode(' ', $this->scopes));

        // Get the Authorization URL
        return $this->issuerUrl;
    }

    /**
     * Process the callback from the OIDC provider.
     * This function should be called by a dedicated callback endpoint.
     */
    public function handleCallback() {
        // Check state parameter to protect against CSRF attacks
        if (!isset($_GET['state']) || $_GET['state'] !== $_SESSION['oidc_state']) {
            die('Invalid state');
        }

        // Exchange the authorization code for tokens
        $tokenResponse = $this->exchangeCodeForToken($_GET['code']);

        if (empty($tokenResponse['id_token'])) {
            die('Failed to receive an ID token');
        }

        // Validate and decode the ID token (consider using a library)
        $userInfo = $this->validateAndExtractUserInfo($tokenResponse['id_token']);
        if (!$userInfo) {
            die('Invalid ID token');
        }

        // At this point, you have user information (e.g., email, name)
        // Map these to a phpList user account.
        $this->loginUser($userInfo);
    }

    /**
     * Exchange the authorization code for tokens.
     */
    private function exchangeCodeForToken($code) {
        $tokenEndpoint = rtrim($this->issuerUrl, '/') . '/protocol/openid-connect/token';

        $postData = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $this->redirectUri,
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        // Use cURL or any HTTP client to POST the data
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $tokenEndpoint);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response, true);
    }

    /**
     * Validate the ID token and extract user information.
     *
     * In production, you should verify the signature, issuer, audience, and expiration.
     * Using a library (e.g., [jumbojett/OpenID-Connect-PHP](https://github.com/jumbojett/OpenID-Connect-PHP)) is recommended.
     */
    private function validateAndExtractUserInfo($idToken) {
        // For a basic implementation, decode the token.
        // WARNING: This does NOT verify the signature!
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            return false;
        }

        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
        // You should check for 'exp', 'iss', and 'aud' here.
        return $payload;
    }

    /**
     * Map the OIDC user info to a phpList user account and log them in.
     */
    private function loginUser($userInfo) {
        // Example: use the email address as the identifier.
        $email = $userInfo['email'] ?? null;
        if (!$email) {
            die('Email not provided by OIDC provider');
        }

        // Check if a user with this email already exists in phpList
        $userId = $this->findUserByEmail($email);
        if (!$userId) {
            // Optionally create a new user if not found
            $userId = $this->createUser($userInfo);
        }

        // Log the user in by setting the phpList session.
        // You may need to call phpList’s internal login functions here.
        setUserSession($userId);

        // Finally, redirect to the main page.
        header('Location: ' . getMainPageUrl());
        exit;
    }

    public function dependencyCheck(): array
    {
        if (version_compare(PHP_VERSION, '7.4.0') < 0) {
            return ['PHP version 7.4 or up'  => false];
        }

        $allowEnable = true;

        return [
            'Simplesaml Configured' => $allowEnable,
            'phpList version 3.6.7 or later' => version_compare(VERSION, '3.6.7') >= 0,
        ];
    }
}
//
//// Instantiate the plugin so that it hooks into phpList.
//$oidcPlugin = new OidcPlugin();
