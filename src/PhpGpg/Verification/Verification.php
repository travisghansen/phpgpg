<?php
namespace PhpGpg\Verification;

use PhpGpg\Signature\Signature;

class Verification
{
    private $_signatures = array();

    private $_data = null;

    public function __toString()
    {
        return $this->getData();
    }

    public function getSignatures()
    {
        return $this->_signatures;
    }

    public function getData()
    {
        return $this->_data;
    }

    public function addSignature(Signature $signature)
    {
        $this->_signatures[] = $signature;
    }

    public function setData($data)
    {
        $this->_data = $data;
    }
}
