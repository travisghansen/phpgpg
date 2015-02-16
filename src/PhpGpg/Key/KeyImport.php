<?php
namespace PhpGpg\Key;

use PhpGpg\Key\Key;

class KeyImport
{
    private $_public_imported = 0;

    private $_public_unchanged = 0;

    private $_private_imported = 0;

    private $_private_unchanged = 0;

    private $_fingerprint = '';

    public function getPublicImported()
    {
        return $this->_public_imported;
    }

    public function getPublicUnchanged()
    {
        return $this->_public_unchanged;
    }

    public function getPrivateImported()
    {
        return $this->_private_imported;
    }

    public function getPrivateUnchanged()
    {
        return $this->_private_unchanged;
    }

    public function getFingerprint()
    {
        return $this->_fingerprint;
    }

    public function setPublicImported($publicImported)
    {
        $this->_public_imported = (int) $publicImported;
    }

    public function setPublicUnchanged($publicUnchanged)
    {
        $this->_public_unchanged = (int) $publicUnchanged;
    }

    public function setPrivateImported($privateImported)
    {
        $this->_private_imported = (int) $privateImported;
    }

    public function setPrivateUnchanged($privateUnchanged)
    {
        $this->_private_unchanged = (int) $privateUnchanged;
    }

    public function setFingerprint($fingerprint)
    {
        $this->_fingerprint = (string) $fingerprint;
    }

}
