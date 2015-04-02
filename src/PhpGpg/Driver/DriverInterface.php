<?php
namespace PhpGpg\Driver;

use PhpGpg\Key\KeyImport;
use PhpGpg\PhpGpg;

interface DriverInterface
{
    /**
     * @return array|bool
     */
    public function getKeys($keyId = null);

    /**
     * @param $data string containing key data
     *
     * @return KeyImport|bool
     */
    public function importKey($data);

    /**
     * @param $key Key|SubKey|string Key or SubKey object or key fingerprint
     *
     * @return bool|string
     */
    public function exportPublicKey($key);

    //public function getFingerprint($keyId);

    /**
     * @return string|bool
     */
    public function encrypt($data);

    /**
     * @return string
     */
    public function sign($data, $mode = PhpGpg::SIG_MODE_CLEAR);

    /**
     * @return string|bool
     */
    public function encryptAndSign($data);

    /**
     * @return string|bool
     */
    public function decrypt($data);

    /**
     * @param $data string
     * @param $signature string signature identifier
     *
     * @return Verification|bool
     */
    public function verify($data, $signature);

    /**
     * @return Verification|bool
     */
    public function decryptAndVerify($data);

    /**
     * @return bool
     */
    public function setArmor($armor);

    /**
     * @return bool
     */
    public function enableArmor();

    /**
     * @return bool
     */
    public function disableArmor();

    /**
     * @return bool
     */
    public function addEncryptKey($key);

    /**
     * @return bool
     */
    public function clearEncryptKeys();

    /**
     * @return bool
     */
    public function addDecryptKey($key, $passphrase = null);

    /**
     * @return bool
     */
    public function clearDecryptKeys();

    /**
     * @param $key Key|SubKey|string
     * @param $passphrase
     *
     * @return bool
     */
    public function addSignKey($key, $passphrase = null);

    /**
     * @return bool
     */
    public function clearSignKeys();

    /**
     * @return bool
     */
    public function deletePublicKey($key);

     /**
      * @return bool
      */
     public function deletePrivateKey($key);
}
