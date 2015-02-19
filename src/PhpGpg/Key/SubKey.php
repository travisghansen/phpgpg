<?php
namespace PhpGpg\Key;

class SubKey extends AbstractKey
{
    private $_id = '';

    private $_algorithm = 0;

    private $_fingerprint = '';

    private $_length = 0;

    private $_creationDate = 0;

    private $_expirationDate = 0;

    private $_canSign = false;

    private $_canEncrypt = false;

    private $_hasPrivate = false;

    private $_isRevoked = false;

    private $_isDisabled = false;

    public function __construct($key = null)
    {
    }

    public function canEncrypt()
    {
        return $this->_canEncrypt;
    }

    public function canSign()
    {
        return $this->_canSign;
    }

    public function getAlgorithm()
    {
        return $this->_algorithm;
    }

    public function getCreationDate()
    {
        return $this->_creationDate;
    }

    public function getExpirationDate()
    {
        return $this->_expirationDate;
    }

    public function getFingerprint()
    {
        return $this->_fingerprint;
    }

    public function getId()
    {
        return $this->_id;
    }

    public function getLength()
    {
        return $this->_length;
    }

    public function hasPrivate()
    {
        return $this->_hasPrivate;
    }

    public function isRevoked()
    {
        return $this->_isRevoked;
    }

    public function setAlgorithm($algorithm)
    {
        $this->_algorithm = (int) $algorithm;
    }

    public function setCanEncrypt($canEncrypt)
    {
        $this->_canEncrypt = (bool) $canEncrypt;
    }

    public function setCanSign($canSign)
    {
        $this->_canSign = (bool) $canSign;
    }

    public function setCreationDate($creationDate)
    {
        $this->_creationDate = (int) $creationDate;
    }

    public function setExpirationDate($expirationDate)
    {
        $this->_expirationDate = (int) $expirationDate;
    }

    public function setFingerprint($fingerprint)
    {
        $this->_fingerprint = (string) $fingerprint;
    }

    public function setHasPrivate($hasPrivate)
    {
        $this->_hasPrivate = (bool) $hasPrivate;
    }

    public function setId($id)
    {
        $this->_id = (string) $id;
    }

    public function setLength($length)
    {
        $this->_length = (int) $length;
    }

    public function setRevoked($isRevoked)
    {
        $this->_isRevoked = (bool) $isRevoked;
    }
}
