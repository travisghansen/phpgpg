<?php
namespace PhpGpg\Key;

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
        foreach ($this->getSubKeys() as $subKey) {
            if ($subKey->canEncrypt()) {
                return true;
            }
        }

        return false;
    }

    public function canSign()
    {
        foreach ($this->getSubKeys() as $subKey) {
            if ($subKey->canSign()) {
                return true;
            }
        }

        return false;
    }

    public function getPrimaryKey()
    {
        $subKeys = $this->getSubKeys();

        return $subKeys[0];
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
