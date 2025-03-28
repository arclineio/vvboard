<?php

namespace App\Protocols;

use App\Utils\Helper;

class Loon
{
    public $flag = 'loon';
    private $servers;
    private $user;

    public function __construct($user, $servers)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $servers = $this->servers;
        $user = $this->user;

        $appName = config('v2board.app_name', 'V2Board');
        header("content-disposition:attachment;filename*=UTF-8''".rawurlencode($appName).".conf");
        header("Subscription-Userinfo: upload={$user['u']}; download={$user['d']}; total={$user['transfer_enable']}; expire={$user['expired_at']}");

        $defaultConfig = base_path() . '/resources/rules/default.loon.conf';
        $customConfig = base_path() . '/resources/rules/custom.loon.conf';
        if (\File::exists($customConfig)) {
            $config = file_get_contents("$customConfig");
        } else {
            $config = file_get_contents("$defaultConfig");
        }

        $proxies = '';
        $proxyGroup = '';
        foreach ($servers as $item) {
            if ($item['type'] === 'shadowsocks') {
                // [Proxy]
                $proxies .= self::buildShadowsocks($user['uuid'], $item);
                // [Proxy Group]
                $proxyGroup .= $item['name'] . ', ';
            }elseif ($item['type'] === 'vmess') {
                // [Proxy]
                $proxies .= self::buildVmess($user['uuid'], $item);
                // [Proxy Group]
                $proxyGroup .= $item['name'] . ', ';
            }elseif ($item['type'] === 'vless' && !$item['flow'] ) { // loon 不支持流控,需要过滤掉
                // [Proxy]
                $proxies .= self::buildVless($user['uuid'], $item);
                // [Proxy Group]
                $proxyGroup .= $item['name'] . ', ';
            }elseif ($item['type'] === 'trojan') {
                // [Proxy]
                $proxies .= self::buildTrojan($user['uuid'], $item);
                // [Proxy Group]
                $proxyGroup .= $item['name'] . ', ';
            }elseif ($item['type'] === 'hysteria' && $item['version'] === 2) { //loon只支持hysteria2
                // [Proxy]
                $proxies .= self::buildHysteria($user['uuid'], $item);
                // [Proxy Group]
                $proxyGroup .= $item['name'] . ', ';
            }
        }

        // Subscription link
        $subsURL = Helper::getSubscribeUrl($user['token']);
        $subsDomain = $_SERVER['HTTP_HOST'];

        $config = file_get_contents("$defaultConfig");
        $config = str_replace('$subs_link', $subsURL, $config);
        $config = str_replace('$subs_domain', $subsDomain, $config);
        $config = str_replace('$proxies', $proxies, $config);
        $config = str_replace('$proxy_group', rtrim($proxyGroup, ', '), $config);

        return $config;
    }


    public static function buildShadowsocks($password, $server)
    {
        if ($server['cipher'] === '2022-blake3-aes-128-gcm') {
            $serverKey = Helper::getServerKey($server['created_at'], 16);
            $userKey = Helper::uuidToBase64($password, 16);
            $password = "{$serverKey}:{$userKey}";
        } elseif ($server['cipher'] === '2022-blake3-aes-256-gcm') {
            $serverKey = Helper::getServerKey($server['created_at'], 32);
            $userKey = Helper::uuidToBase64($password, 32);
            $password = "{$serverKey}:{$userKey}";
        }
        $config = [
            "{$server['name']}=Shadowsocks",
            "{$server['host']}",
            "{$server['port']}",
            "{$server['cipher']}",
            "{$password}",
            'fast-open=true',
            'udp=true'
        ];
        $config = array_filter($config);
        $uri = implode(',', $config);
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildVmess($uuid, $server)
    {
        $config = [
            "{$server['name']}=vmess",
            "{$server['host']}",
            "{$server['port']}",
            $server['networkSettings']['security'] ?? 'auto',
            "{$uuid}",
            'fast-open=false',
            'udp=true',
            "alterId=0"
        ];

        if ($server['network'] === 'tcp') {
            array_push($config, 'transport=tcp');
            if ($server['networkSettings']) {
                $tcpSettings = $server['networkSettings'];
                if (isset($tcpSettings['header']['type']) && !empty($tcpSettings['header']['type']) && $tcpSettings['header']['type'] == 'http')
                    $config = str_replace('transport=tcp', "transport={$tcpSettings['header']['type']}", $config);
                if (isset($tcpSettings['header']['request']['path'][0]) && !empty($tcpSettings['header']['request']['path'][0]))
                    array_push($config, "path={$tcpSettings['header']['request']['path'][0]}");
                if (isset($tcpSettings['header']['request']['headers']['Host'][0]) && !empty($tcpSettings['header']['request']['headers']['Host'][0]))
                    array_push($config, "host={$tcpSettings['header']['request']['headers']['Host'][0]}");
            }
        }
        if ($server['tls']) {
            array_push($config, 'over-tls=true');
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'];
                if (isset($tlsSettings['allowInsecure']) && !empty($tlsSettings['allowInsecure']))
                    array_push($config, 'skip-cert-verify=' . ($tlsSettings['allowInsecure'] ? 'true' : 'false'));
                if (isset($tlsSettings['serverName']) && !empty($tlsSettings['serverName']))
                    array_push($config, "tls-name={$tlsSettings['serverName']}");
            }
        }
        if ($server['network'] === 'ws') {
            array_push($config, 'transport=ws');
            if ($server['networkSettings']) {
                $wsSettings = $server['networkSettings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    array_push($config, "path={$wsSettings['path']}");
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    array_push($config, "host={$wsSettings['headers']['Host']}");
            }
        }

        $uri = implode(',', $config);
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildVless($uuid, $server)
    {
        $config = [
            "{$server['name']}=vless",
            "{$server['host']}",
            "{$server['port']}",
            "{$uuid}",
            'fast-open=false',
            'udp=true',
            "alterId=0"
        ];

        if ($server['network'] === 'tcp') {
            array_push($config, 'transport=tcp');
            if ($server['network_settings']) {
                $tcpSettings = $server['network_settings'];
                if (isset($tcpSettings['header']['type']) && !empty($tcpSettings['header']['type']) && $tcpSettings['header']['type'] == 'http')
                    $config = str_replace('transport=tcp', "transport={$tcpSettings['header']['type']}", $config);
                if (isset($tcpSettings['header']['request']['path'][0]) && !empty($tcpSettings['header']['request']['path'][0]))
                    array_push($config, "path={$tcpSettings['header']['request']['path'][0]}");
                if (isset($tcpSettings['header']['request']['headers']['Host'][0]) && !empty($tcpSettings['header']['request']['headers']['Host'][0]))
                    array_push($config, "host={$tcpSettings['header']['request']['headers']['Host'][0]}");
            }
        }
        if ($server['tls'] === 1) {
            array_push($config, 'over-tls=true');
            if ($server['network'] === 'tcp')

            if ($server['tls_settings']) {
                $tlsSettings = $server['tls_settings'];
                if (isset($tlsSettings['allow_insecure']) && !empty($tlsSettings['allow_insecure']))
                    array_push($config, 'skip-cert-verify=' . ($tlsSettings['allow_insecure'] ? 'true' : 'false'));
                if (isset($tlsSettings['server_name']) && !empty($tlsSettings['server_name']))
                    array_push($config, "tls-name={$tlsSettings['server_name']}");
            }
        }elseif($server['tls'] === 2){ // reality 暂不被 loon 支持
            return '';
        }
        if ($server['network'] === 'ws') {
            array_push($config, 'transport=ws');
            if ($server['network_settings']) {
                $wsSettings = $server['network_settings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    array_push($config, "path={$wsSettings['path']}");
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    array_push($config, "host={$wsSettings['headers']['Host']}");
            }
        }

        $uri = implode(',', $config);
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildTrojan($password, $server)
    {
        $config = [
            "{$server['name']}=trojan",
            "{$server['host']}",
            "{$server['port']}",
            "{$password}",
            $server['server_name'] ? "tls-name={$server['server_name']}" : "",
            'fast-open=false',
            'udp=true'
        ];
        if (!empty($server['allow_insecure'])) {
            array_push($config, $server['allow_insecure'] ? 'skip-cert-verify=true' : 'skip-cert-verify=false');
        }
        if (isset($server['network']) && (string)$server['network'] === 'ws') {
            array_push($config, 'ws=true');
            if ($server['network_settings']) {
                $wsSettings = $server['network_settings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    array_push($config, "ws-path={$wsSettings['path']}");
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    array_push($config, "ws-headers=Host:{$wsSettings['headers']['Host']}");
            }
        }
        $config = array_filter($config);
        $uri = implode(',', $config);
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildHysteria($password, $server)
    {

        $parts = explode(",",$server['port']);
        $firstPart = $parts[0];
        if (strpos($firstPart, '-') !== false) {
            $range = explode('-', $firstPart);
            $firstPort = $range[0];
        } else {
            $firstPort = $firstPart;
        }

        $config = [
            "{$server['name']}=hysteria2",
            "{$server['host']}",
            "{$firstPort}",
            "password={$password}",
            "download-bandwidth={$server['up_mbps']}",
            $server['server_name'] ? "sni={$server['server_name']}" : "",
            'udp=true'
        ];
        if (!empty($server['insecure'])) {
            array_push($config, $server['insecure'] ? 'skip-cert-verify=true' : 'skip-cert-verify=false');
        }
        $config = array_filter($config);
        $uri = implode(',', $config);
        $uri .= "\r\n";
        return $uri;
    }
}
