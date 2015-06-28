<?php
namespace PhpGpg\Driver\GnuPG\GpgMe;

class Wrapper
{
    private $_res;
    private $_homedir;

    public function __construct($homedir = null)
    {
        $this->_homedir = $homedir;
        $this->_res = new \gnupg();
        $this->_res->seterrormode( \gnupg::ERROR_EXCEPTION );
    }

    private function setHomedir()
    {
        if ($this->_homedir !== null) {
            $this->clearHomedir();
            $homedir = $this->_homedir;
            putenv("GNUPGHOME=${homedir}");
        }
    }

    private function clearHomedir()
    {
        if ($this->_homedir !== null) {
            putenv("GNUPGHOME");
        }
    }

    public function __call($name, $arguments)
    {
        $this->setHomedir();
        $value = call_user_func_array(array($this->_res, $name), $arguments);
        $this->clearHomedir();

        return $value;
    }
}
