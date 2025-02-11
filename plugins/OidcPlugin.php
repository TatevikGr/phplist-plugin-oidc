<?php

require_once __DIR__ . '/OidcPlugin/vendor/autoload.php';
require_once dirname(__FILE__, 2) . '/defaultplugin.php';
$config = require_once __DIR__ . '/OidcPlugin/config.php';

class OidcPlugin extends phplistPlugin
{
    public $name = 'oidc';
    public $description = 'Login to phpList with oidc';
    public $version = '0.1';
    private $clientId;
    private $clientSecret;
    private $issuerUrl;
    private $redirectUri;
    private $db;

    public function __construct()
    {
        parent::__construct();
        global $config;
        $this->db = $GLOBALS['tables'];
        $requiredKeys = ['OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_ISSUER_URL', 'OIDC_REDIRECT_URI'];

        foreach ($requiredKeys as $key) {
            if (!defined($key) && !array_key_exists($key, $config)) {
                throw new RuntimeException("Missing required config: $key");
            }
        }
        $this->clientId     = defined('OIDC_CLIENT_ID') ? OIDC_CLIENT_ID : ($config['OIDC_CLIENT_ID'] ?? null);
        $this->clientSecret = defined('OIDC_CLIENT_SECRET') ? OIDC_CLIENT_SECRET : ($config['OIDC_CLIENT_SECRET'] ?? null);
        $this->issuerUrl    = defined('OIDC_ISSUER_URL') ? OIDC_ISSUER_URL : ($config['OIDC_ISSUER_URL'] ?? null);
        $this->redirectUri  = defined('OIDC_REDIRECT_URI') ? OIDC_REDIRECT_URI : ($config['OIDC_REDIRECT_URI'] ?? null);
    }

    public function login()
    {
        if (!isset($_GET['oidc'])) {
            return false;
        }
        $oidc = new Jumbojett\OpenIDConnectClient(
            $this->issuerUrl,
            $this->clientId,
            $this->clientSecret,
        );
        $oidc->setRedirectURL($this->redirectUri);
        $oidc->addScope(explode(' ', 'openid email profile'));

        try {
            $oidc->authenticate();
            $userInfo = $oidc->requestUserInfo();
            $payload = $oidc->getAccessTokenPayload();
        } catch (Jumbojett\OpenIDConnectClientException $e) {
            $_SESSION['action_result'] = "Authentication failed: " . $e->getMessage();
            header("Location: " . $_SERVER['HTTP_REFERER']);
            exit;
        }

        $privileges = null;
        $superuser = 1;
        $login = $payload->preferred_username;

        $admindata = Sql_Fetch_Assoc_Query(sprintf(
                'select loginname,password,disabled,id,superuser,privileges from %s where loginname="%s"',
                $this->db['admin'],
                addslashes($login))
        );

        if (!$admindata) {
            if (!$privileges) {
                $privileges = serialize([
                    'subscribers' => true,
                    'campaigns' => true,
                    'statistics' => true,
                    'settings' => true
                ]);
            }

            $userCreated = Sql_Query(sprintf(
                'insert into %s (loginname,email,namelc,created,privileges,superuser) values("%s","%s","%s",now(),"%s", "%d")',
                $this->db['admin'],
                addslashes($login),
                sql_escape($userInfo->email),
                strtolower(addslashes($login)),
                sql_escape($privileges),
                $superuser
            ));
            $admindata = Sql_Fetch_Assoc_Query(sprintf(
                'select loginname,password,disabled,id,superuser,privileges from %s where loginname="%s"',
                $this->db['admin'],
                addslashes($login)
            ));
            if ($payload->sub && !$userCreated || !$admindata) {
                return false;
            }
        }

        $_SESSION['adminloggedin'] = $GLOBALS['remoteAddr'];
        $_SESSION['logindetails'] = [
            'adminname' => $login,
            'id' => $admindata['id'],
            'superuser' => $admindata['superuser']
        ];

        Sql_Query(sprintf('insert into %s (moment,adminid,remote_ip4,remote_ip6,sessionid,active) 
        values(%d,%d,"%s","%s","%s",1)',
            $this->db['admin_login'],time(),$admindata['id'],getClientIP(),"",session_id()));

        if ($admindata['privileges']) {
            $_SESSION['privileges'] = unserialize($admindata['privileges']);
        }

        return true;
    }

    public function dependencyCheck(): array
    {
        if (version_compare(PHP_VERSION, '7.0.0') < 0) {
            return ['PHP version 7.0 or up'  => false];
        }

        $allowEnable = true;

        return [
            'Oidc Configured' => $allowEnable,
            'phpList version 3.7.0 or later' => version_compare(VERSION, '3.7.0') >= 0,
        ];
    }
}
