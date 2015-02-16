<?php
namespace PhpGpg\Key;

use PhpGpg\Key\SubKey;
use PhpGpg\UserId\UserId;

class Key extends AbstractKey
{
    private $_userIds = array();

    private $_subKeys = array();


    public function addSubKey(SubKey $subKey)
    {
        $this->_subKeys[] = $subKey;
    }

    public function addUserId(UserId $userId)
    {
        $this->_userIds[] = $userId;
    }

    public function canEncrypt()
    {

    }

    public function canSign()
    {

    }

    public function getPrimaryKey()
    {

    }

    public function getSubKeys()
    {
        return $this->_subKeys;
    }

    public function getUserIds()
    {
        return $this->_userIds;
    }

}
