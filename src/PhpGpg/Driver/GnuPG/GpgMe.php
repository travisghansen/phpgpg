<?php
namespace PhpGpg\Driver\GnuPG;

use PhpGpg\Driver\AbstractDriver;
use PhpGpg\Driver\DriverInterface;
use PhpGpg\Key\Key;
use PhpGpg\Key\KeyImport;
use PhpGpg\Key\SubKey;
use PhpGpg\PhpGpg;
use PhpGpg\Signature\Signature;
use PhpGpg\UserId\UserId;
use PhpGpg\Verification\Verification;

/**
 * @link http://php.net/manual/en/ref.gnupg.php
 */
class GpgMe extends AbstractDriver implements DriverInterface
{
    private $_res = null;
    private $errorMode = PhpGpg::ERROR_MODE_SILENT;

    public function __construct($homedir = null, $options = array())
    {
        $this->_res = new GpgMe\Wrapper($homedir);
    }

    /**
     * @return GpgMe\Wrapper
     */
    private function getResource()
    {
        return $this->_res;
    }

    /**
     * (non-PHPdoc)
     * @see \PhpGpg\Driver\DriverInterface::setErrorMode()
     */
    public function setErrorMode($mode)
    {
        $this->errorMode = $mode;
    }

    /**
     * (non-PHPdoc)
     * @see \PhpGpg\Driver\DriverInterface::getErrorMode()
     */
    public function getErrorMode()
    {
        return $this->errorMode;
    }

    public function setArmor($armor)
    {
        return $this->getResource()->setarmor((bool) $armor);
    }

    public function enableArmor()
    {
        return $this->setArmor(true);
    }

    public function disableArmor()
    {
        return $this->setArmor(false);
    }

    public function encrypt($data)
    {
        return $this->getResource()->encrypt($data);
    }

    public function sign($data, $mode = PhpGpg::SIG_MODE_CLEAR)
    {
        switch ($mode) {
            default:
            case 1:
                $d_mode = GNUPG_SIG_MODE_CLEAR;
                break;
            case 2:
                $d_mode = GNUPG_SIG_MODE_NORMAL;
                break;
            case 3:
                $d_mode = GNUPG_SIG_MODE_DETACH;
                break;
        }
        $this->getResource()->setsignmode($d_mode);

        return $this->getResource()->sign($data);
    }

    public function encryptAndSign($data)
    {
        return $this->getResource()->encryptsign($data);
    }

    public function decrypt($data)
    {
        return $this->getResource()->decrypt($data);
    }

    public function verify($data, $signature)
    {
        $plaintext = null;
        $info = $this->getResource()->verify($data, $signature, $plaintext);

        $result = new Verification();
        $result->setData($plaintext);
        foreach ($info as $sig) {
            $signature = new Signature();
            $signature->setCreationDate($sig['timestamp']);
            $signature->setFingerprint($sig['fingerprint']);

            $result->addSignature($signature);
        }

        return $result;
    }

    public function decryptAndVerify($data)
    {
        $plaintext = null;
        $info = $this->getResource()->decryptverify($data, $plaintext);

        $result = new Verification();
        $result->setData($plaintext);
        foreach ($info as $sig) {
            $signature = new Signature();
            $signature->setCreationDate($sig['timestamp']);
            $signature->setFingerprint($sig['fingerprint']);

            $result->addSignature($signature);
        }

        return $result;
    }

    public function getKeys($keyId = null)
    {
        $keys = array();
        $data = $this->getResource()->keyinfo($keyId);

        foreach ($data as $kd) {
            $key = new Key();
            foreach ($kd['subkeys'] as $skd) {
                $subKey = new SubKey();
                $subKey->setCanEncrypt($skd['can_encrypt']);
                $subKey->setCanSign($skd['can_sign']);
                $subKey->setCreationDate($skd['timestamp']);
                $subKey->setExpirationDate($skd['expires']);
                $subKey->setFingerprint($skd['fingerprint']);
                $subKey->setHasPrivate(false);
                $subKey->setId($skd['keyid']);
                $subKey->setRevoked($skd['revoked']);
                $subKey->setDisabled($skd['disabled']);
                //$subKey->setLength($skd['can_encrypt']);
                //$subKey->setAlgorithm();

                $key->addSubKey($subKey);
            }

            foreach ($kd['uids'] as $uid) {
                $userId = new UserId();
                $userId->setName($uid['name']);
                $userId->setComment($uid['comment']);
                $userId->setEmail($uid['email']);
                $userId->setUid($uid['uid']);
                $userId->setIsRevoked($uid['revoked']);
                $userId->setIsValid(($uid['invalid']) ? false : true);

                $key->addUserId($userId);
            }

            $keys[] = $key;
        }

        return $keys;
    }

    public function addDecryptKey($key, $passphrase = null)
    {
        $fingerprint = null;

        if ($key instanceof Key) {
            foreach ($key->getSubKeys() as $subKey) {
                $this->getResource()->adddecryptkey($subKey->getFingerprint(), $passphrase);
            }

            return true;
        } elseif ($key instanceof SubKey) {
            $fingerprint = $key->getFingerprint();
        } elseif (is_string($key)) {
            $fingerprint = $key;
        }

        return $this->getResource()->adddecryptkey($fingerprint, $passphrase);
    }

    public function clearDecryptKeys()
    {
        return $this->getResource()->cleardecryptkeys();
    }

    public function addEncryptKey($key)
    {
        $fingerprint = null;

        if ($key instanceof Key) {
            foreach ($key->getSubKeys() as $subKey) {
                if ($subKey->canEncrypt()) {
                    $this->getResource()->addencryptkey($subKey->getFingerprint());
                }
            }

            return true;
        } elseif ($key instanceof SubKey) {
            $fingerprint = $key->getFingerprint();
        } elseif (is_string($key)) {
            $fingerprint = $key;
        }

        return $this->getResource()->addencryptkey($fingerprint);
    }

    public function clearEncryptKeys()
    {
        return $this->getResource()->cleardecryptkeys();
    }

    public function addSignKey($key, $passphrase = null)
    {
        $fingerprint = null;

        if ($key instanceof Key) {
            foreach ($key->getSubKeys() as $subKey) {
                if ($subKey->canSign()) {
                    $this->getResource()->addsignkey($subKey->getFingerprint());
                }
            }

            return true;
        } elseif ($key instanceof SubKey) {
            $fingerprint = $key->getFingerprint();
        } elseif (is_string($key)) {
            $fingerprint = $key;
        }

        return $this->getResource()->addsignkey($fingerprint, $passphrase);
    }

    public function clearSignKeys()
    {
        return $this->getResource()->clearsignkeys;
    }

    public function importKey($data)
    {
        $data = $this->getResource()->import($data);
        if ($data === false) {
            return false;
        }

        $result = new KeyImport();
        $result->setPublicImported($data['imported']);
        $result->setPublicUnchanged($data['unchanged']);
        $result->setPrivateImported($data['secretimported']);
        $result->setPrivateUnchanged($data['secretunchanged']);
        $result->setFingerprint($data['fingerprint']);

        return $result;
    }

    public function exportPublicKey($key)
    {
        $fingerprint = null;
        $data = null;

        if ($key instanceof Key) {
            foreach ($key->getSubKeys() as $subKey) {
                $data .= $this->getResource()->export($subKey->getFingerprint());
            }

            return $data;
        } elseif ($key instanceof SubKey) {
            $fingerprint = $key->getFingerprint();
        } elseif (is_string($key)) {
            $fingerprint = $key;
        }
        $data = $this->getResource()->export($fingerprint);

        return $data;
    }

    public function deletePublicKey($key)
    {
        $fingerprint = null;

        if ($key instanceof Key) {
            foreach ($key->getSubKeys() as $subKey) {
                $this->getResource()->deletekey($subKey->getFingerprint());
            }

            return true;
        } elseif ($key instanceof SubKey) {
            $fingerprint = $key->getFingerprint();
        } elseif (is_string($key)) {
            $fingerprint = $key;
        }

        return $this->getResource()->deletekey($fingerprint);
    }

    public function deletePrivateKey($key)
    {
        $fingerprint = null;

        if ($key instanceof Key) {
            foreach ($key->getSubKeys() as $subKey) {
                $this->getResource()->deletekey($subKey->getFingerprint(), true);
            }

            return true;
        } elseif ($key instanceof SubKey) {
            $fingerprint = $key->getFingerprint();
        } elseif (is_string($key)) {
            $fingerprint = $key;
        }

        return $this->getResource()->deletekey($fingerprint, true);
    }
}
