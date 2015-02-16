<?php
namespace PhpGpg\UserId;

class UserId
{
    private $_name = '';

    private $_comment = '';

    private $_email = '';

    private $_uid = '';

    private $_isRevoked = false;

    private $_isValid = false;

    public function getName()
    {
        return $this->_name;
    }

    public function getComment()
    {
        return $this->_comment;
    }

    public function getEmail()
    {
        return $this->_email;
    }

    public function getUid()
    {
        return $this->_uid;
    }

    public function getIsRevoked()
    {
        return $this->_isRevoked;
    }

    public function getIsValid()
    {
        return $this->_isValid;
    }

    public function setName($name)
    {
        $this->_name = strval($name);
    }

    public function setComment($comment)
    {
        $this->_comment = strval($comment);
    }

    public function setEmail($email)
    {
        $this->_email = strval($email);
    }

    public function setUid($uid)
    {
        $this->_uid = strval($uid);
    }

    public function setIsRevoked($isRevoked)
    {
        $this->_isRevoked = (bool) $isRevoked;
    }

    public function setIsValid($isValid)
    {
        $this->_isValid = (bool) $isValid;
    }
}
