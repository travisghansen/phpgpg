<?php
namespace PhpGpg\Driver;

use PhpGpg\Key\KeyImport;
use PhpGpg\PhpGpg;
use PhpGpg\Verification\Verification;

interface DriverInterface
{

    /**
     *
     * @return array
     */
    public function getKeys($keyId = null);

    /**
     *
     * @return KeyImport|bool
     */
    public function importKey($data);

    /**
     *
     * @return bool|Key
     */
    public function exportPublicKey($key);

    //public function getFingerprint($keyId);

    /**
     *
     * @return string|bool
     */
    public function encrypt($data);

    /**
     *
     * @return string
     */
    public function sign($data, $mode = PhpGpg::SIG_MODE_CLEAR);

    /**
     *
     * @return string|bool
     */
    public function encryptAndSign($data);

    /**
     *
     * @return string|bool
     */
    public function decrypt($data);

    /**
     *
     * @return VerifyResult|bool
     */
    public function verify($data, $signature);

    /**
     *
     * @return VerifyResult|bool
     */
    public function decryptAndVerify($data);

    /**
     *
     * @return bool
     */
    public function setArmor($armor);

    /**
     *
     * @return bool
     */
    public function enableArmor();

    /**
     *
     * @return bool
     */
    public function disableArmor();

    /**
     *
     * @return bool
     */
    public function addEncryptKey($key);

    /**
     *
     * @return bool
     */
    public function clearEncryptKeys();

    /**
     *
     * @return bool
     */
    public function addDecryptKey($key, $passphrase = null);

    /**
     *
     * @return bool
     */
    public function clearDecryptKeys();

    /**
     *
     * @return bool
     */
    public function addSignKey($key, $passphrase = null);

    /**
     *
     * @return bool
     */
    public function clearSignKeys();

    /**
     *
     * @return bool
     */
    public function deletePublicKey($key);

    /**
     *
     * @return bool
     */
     public function deletePrivateKey($key);
}
