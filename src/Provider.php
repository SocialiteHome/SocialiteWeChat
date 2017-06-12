<?php

namespace Socialite\SocialiteWeChat;

use Exception;
use Socialite\SocialiteManager\AbstractProvider;

/**
 * 提示：包含微信网页授权和网站应用微信登录两种方式，使用 scope 来区分:
 * 微信网页授权 scope 包含两种: snsapi_base、snsapi_userinfo，若同时使用则以 snsapi_userinfo 为准.
 * 网站应用微信登录 scope 目前只有: snsapi_login.
 *
 * @link https://mp.weixin.qq.com/wiki 微信网页授权文档
 * @link https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419316505&token=&lang=zh_CN 微信网站应用微信登录文档
 */
class Provider extends AbstractProvider
{
    /**
     * @var string
     */
    protected $openId;

    /**
     * {@inheritdoc}.
     */
    protected $scopes = ['snsapi_base', 'snsapi_userinfo'];

    /**
     * The base url of WeChat API.
     *
     * @var string
     */
    protected $baseUrl = 'https://api.weixin.qq.com/sns';

    /**
     * The authentication URL.
     *
     * @var string
     */
    protected $authBaseUrl = 'https://open.weixin.qq.com/connect';

    /**
     * set Open Id.
     *
     * @param string $openId
     */
    public function setOpenId($openId)
    {
        $this->openId = $openId;

        return $this;
    }

    /**
     * {@inheritdoc}.
     */
    protected function getAuthUrl($state)
    {
        $path = 'oauth2/authorize';

        if (in_array('snsapi_login', $this->scopes)) {
            $path = 'qrconnect';
        }

        return $this->buildAuthUrlFromBase($this->authBaseUrl."/{$path}", $state);
    }

    /**
     * {@inheritdoc}.
     */
    protected function buildAuthUrlFromBase($url, $state)
    {
        $query = http_build_query($this->getCodeFields($state), '', '&', $this->encodingType);

        return $url.'?'.$query.'#wechat_redirect';
    }

    /**
     * {@inheritdoc}.
     */
    protected function getCodeFields($state = null)
    {
        return [
            'state' => $state,
            'response_type' => 'code',
            'appid' => $this->clientId,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->scopes, $this->scopeSeparator),
        ];
    }

    /**
     * {@inheritdoc}.
     */
    protected function getTokenUrl()
    {
        return $this->baseUrl.'/oauth2/access_token';
    }

    /**
     * {@inheritdoc}.
     */
    protected function getUserByToken($token)
    {
        $params = [
            'access_token' => $token,
            'openid' => $this->openId,
            'lang' => 'zh_CN',
        ];

        $response = $this->getHttp()->get($this->baseUrl.'/userinfo', $params);

        return $this->getHttp()->parseJson($response->getBody());
    }

    /**
     * {@inheritdoc}.
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id' => array_get($user, 'openid'),
            'nickname' => array_get($user, 'nickname'),
            'avatar' => array_get($user, 'headimgurl'),
            'name' => null,
            'email' => null,
        ]);
    }

    /**
     * {@inheritdoc}.
     */
    protected function getTokenFields($code)
    {
        return [
            'code' => $code,
            'appid' => $this->clientId,
            'secret' => $this->clientSecret,
            'grant_type' => 'authorization_code',
        ];
    }

    /**
     * {@inheritdoc}.
     */
    public function getAccessTokenResponse($code)
    {
        $http = $this->getHttp();
        $response = $http->get($this->getTokenUrl(), $this->getTokenFields($code));
        $contents = $http->parseJson($response->getBody());

        $this->checkResponse($contents);
        $this->setOpenId($contents['openid']);

        return $contents;
    }

    /**
     * {@inheritdoc}.
     */
    public function scopes(array $scopes)
    {
        $this->scopes = array_unique($scopes);

        return $this;
    }

    /**
     * Check the contents.
     *
     * @param array $contents
     *
     * @throws Exception
     */
    protected function checkResponse(array $contents)
    {
        if (isset($contents['errcode']) && 0 !== $contents['errcode']) {
            if (empty($contents['errmsg'])) {
                $contents['errmsg'] = 'Unknown';
            }

            throw new Exception($contents['errmsg'], $contents['errcode']);
        }
    }
}
