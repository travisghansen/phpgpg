<?php

define('TEST1_PUB_FILE', __DIR__.'/data/keys/TEST1.pub');
define('TEST1_SEC_FILE', __DIR__.'/data/keys/TEST1.sec');
define('TEST1_ID', '37CFA307');

define('TEST2_PUB_FILE', __DIR__.'/data/keys/TEST2.pub');
define('TEST2_SEC_FILE', __DIR__.'/data/keys/TEST2.sec');
define('TEST2_ID', '202D45BB');

define('TEST3_PUB_FILE', __DIR__.'/data/keys/TEST3.pub');
define('TEST3_SEC_FILE', __DIR__.'/data/keys/TEST3.sec');
define('TEST3_ID', '425CE496');
define('TEST3_PASSPHRASE', 'test1234test');

define('NVIDIA_PUB_FILE', __DIR__.'/data/keys/NVIDIA.pub');
define('NVIDIA_ID', '09BA9635');

define('PERCONA_PUB_FILE', __DIR__.'/data/keys/PERCONA.pub');
define('PERCONA_ID', '93C89E28');

define('MYSQL_PUB_FILE', __DIR__.'/data/keys/MYSQL.pub');
define('MYSQL_ID', '5072E1F5');

$base_keychain_dir = __DIR__.'/data/keychains';

PhpGpg\PhpGpg::setDefaultDriver('\PhpGpg\Driver\GnuPG\Cli');
//PhpGpg\PhpGpg::setDefaultDriver('\PhpGpg\Driver\GnuPG\GpgMe');
$resource_1 = new PhpGpg\PhpGpg($base_keychain_dir.'/1');
//PhpGpg\PhpGpg::setDefaultDriver('\PhpGpg\Driver\GnuPG\GpgMe');
$resource_2 = new PhpGpg\PhpGpg($base_keychain_dir.'/2');
//PhpGpg\PhpGpg::setDefaultDriver('\PhpGpg\Driver\GnuPG\Cli');
$resource_tmp = new PhpGpg\PhpGpg($base_keychain_dir.'/tmp');
