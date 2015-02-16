<?php
namespace PhpGpg\Signature;

class Signature
{
    private $_fingerprint = '';

    private $_creationDate = 0;

    public function getCreationDate()
    {
        return $this->_creationDate;
    }

    public function getFingerprint()
    {
        return $this->_fingerprint;
    }

    public function setCreationDate($creationDate)
    {
        $this->_creationDate = (int) $creationDate;
    }

    public function setFingerprint($fingerprint)
    {
        $this->_fingerprint = $fingerprint;
    }
}
