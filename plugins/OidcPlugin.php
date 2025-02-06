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
        $this->clientId     = $config['OIDC_CLIENT_ID'];
        $this->clientSecret = $config['OIDC_CLIENT_SECRET'];
        $this->issuerUrl    = $config['OIDC_ISSUER_URL'];
        $this->redirectUri  = $config['OIDC_REDIRECT_URI'];
    }

    public function login()
    {
        if (isset($_GET['oidc'])) {
            $oidc = new Jumbojett\OpenIDConnectClient(
                $this->issuerUrl,
                $this->clientId,
                $this->clientSecret,
            );
            $oidc->setRedirectURL($this->redirectUri);
            $oidc->addScope(explode(' ', 'openid email profile'));

            $oidc->authenticate();
            $userInfo = $oidc->requestUserInfo();
            $payload = $oidc->getAccessTokenPayload();

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
    }

    public function dependencyCheck(): array
    {
        if (version_compare(PHP_VERSION, '7.4.0') < 0) {
            return ['PHP version 7.4 or up'  => false];
        }

        $allowEnable = true;

        return [
            'Oidc Configured' => $allowEnable,
            'phpList version 3.6.7 or later' => version_compare(VERSION, '3.6.7') >= 0,
        ];
    }
}
