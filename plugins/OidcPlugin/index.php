<?php



try {
    require_once 'config.php';
    require_once 'vendor/autoload.php';
    $oidc = new Jumbojett\OpenIDConnectClient(
        $config['OIDC_ISSUER_URL'],
        $config['OIDC_CLIENT_ID'],
        $config['OIDC_CLIENT_SECRET'],
    );

    $oidc->setRedirectURL($config['OIDC_REDIRECT_URI']);
    $oidc->addScope(explode(' ', 'openid email profile'));
    $oidc->authenticate();

    $userInfo = $oidc->requestUserInfo();

    var_dump($userInfo);
} catch (\Throwable $e) {
    var_dump($e); die;
}

