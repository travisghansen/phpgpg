<?php
namespace PhpGpg\Driver\GnuPG;

use PhpGpg\Driver\DriverInterface;
use PhpGpg\Driver\GnuPG\Cli\AbstractCli;
use PhpGpg\Driver\GnuPG\Cli\DecryptStatusHandler;
use PhpGpg\Driver\GnuPG\Cli\VerifyStatusHandler;
use PhpGpg\Key\Key;
use PhpGpg\Key\KeyImport;
use PhpGpg\Key\SubKey;
use PhpGpg\PhpGpg;

class Cli extends AbstractCli implements DriverInterface
{
    /**
     * No formatting is performed.
     *
     * Example: C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4
     *
     * @see Crypt_GPG::getFingerprint()
     */
    const FORMAT_NONE = 1;

    /**
     * Fingerprint is formatted in the format used by the GnuPG gpg command's
     * default output.
     *
     * Example: C3BC 615A D9C7 66E5 A85C  1F27 16D2 7458 B1BB A1C4
     *
     * @see Crypt_GPG::getFingerprint()
     */
    const FORMAT_CANONICAL = 2;

    /**
     * Fingerprint is formatted in the format used when displaying X.509
     * certificates.
     *
     * Example: C3:BC:61:5A:D9:C7:66:E5:A8:5C:1F:27:16:D2:74:58:B1:BB:A1:C4
     *
     * @see Crypt_GPG::getFingerprint()
     */
    const FORMAT_X509 = 3;

    /**
     * Use to specify ASCII armored mode for returned data.
     */
    const ARMOR_ASCII = true;

    /**
     * Use to specify binary mode for returned data.
     */
    const ARMOR_BINARY = false;

    /**
     * Use to specify that line breaks in signed text should be normalized.
     */
    const TEXT_NORMALIZED = true;

    /**
     * Use to specify that line breaks in signed text should not be normalized.
     */
    const TEXT_RAW = false;

    /**
     * Engine used to control the GPG subprocess.
     */
    protected $engine = null;

    /**
     * Keys used to encrypt.
     */
    protected $encryptKeys = array();

    /**
     * Keys used to decrypt.
     */
    protected $signKeys = array();

    /**
     * Keys used to sign.
     */
    protected $decryptKeys = array();

    /**
     * If armor is enabled or not
     */
    protected $armor = true;

    public function setArmor($armor)
    {
        $this->armor = (bool) $armor;

        return true;
    }

    public function enableArmor()
    {
        return $this->setArmor(true);
    }

    public function disableArmor()
    {
        return $this->setArmor(false);
    }

    public function __construct($homedir, $options)
    {
        if (!empty($homedir)) {
            $options['homedir'] = $homedir;
            //$options['debug'] = true;
        }
        parent::__construct($options);
    }

    /**
     * Gets the available keys in the keyring.
     *
     * Calls GPG with the <kbd>--list-keys</kbd> command and grabs keys. See
     * the first section of <b>doc/DETAILS</b> in the
     * {@link http://www.gnupg.org/download/ GPG package} for a detailed
     * description of how the GPG command output is parsed.
     *
     * @param string $keyId optional. Only keys with that match the specified
     *                      pattern are returned. The pattern may be part of
     *                      a user id, a key id or a key fingerprint. If not
     *                      specified, all keys are returned.
     *
     * @return array an array of Key objects. If no keys
     *               match the specified <kbd>$keyId</kbd> an empty array is
     *               returned.
     */
    public function getKeys($keyId = '')
    {
        try {
            return parent::_getKeys($keyId);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Imports a public or private key into the keyring.
     *
     * @param string $data the key data to be imported.
     *
     * @return KeyImport|bool
     */
    public function importKey($data)
    {
        try {
            $result = $this->_importKey($data);
            $keyImport = new KeyImport();
            $keyImport->setPublicImported($result['public_imported']);
            $keyImport->setPublicUnchanged($result['public_unchanged']);
            $keyImport->setPrivateImported($result['private_imported']);
            $keyImport->setPrivateUnchanged($result['private_unchanged']);
            $keyImport->setFingerprint($result['fingerprint']);

            return $keyImport;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Imports a public or private key into the keyring.
     *
     * @param string $key the key to be imported.
     *
     * @return array an associative array containing the following elements:
     *               - <kbd>fingerprint</kbd>       - the fingerprint of the
     *               imported key,
     *               - <kbd>public_imported</kbd>   - the number of public
     *               keys imported,
     *               - <kbd>public_unchanged</kbd>  - the number of unchanged
     *               public keys,
     *               - <kbd>private_imported</kbd>  - the number of private
     *               keys imported,
     *               - <kbd>private_unchanged</kbd> - the number of unchanged
     *               private keys.
     *
     * @throws Exception if the key data is missing or if the
     *                   data is is not valid key data.
     * @throws Exception if the key file is not readable.
     * @throws Exception if an unknown or unexpected error occurs.
     *                   Use the <kbd>debug</kbd> option and file a bug report if these
     *                   exceptions occur.
     */
    protected function _importKey($key)
    {
        $result = array();

        $input = strval($key);
        if ($input == '') {
            throw new \Exception(
                'No valid GPG key data found.',
                self::ERROR_NO_DATA
            );
        }

        $arguments = array();
        $version   = $this->engine->getVersion();

        if (version_compare($version, '1.0.5', 'ge')
            && version_compare($version, '1.0.7', 'lt')
        ) {
            $arguments[] = '--allow-secret-key-import';
        }

        $this->engine->reset();
        $this->engine->addStatusHandler(
            array($this, 'handleImportKeyStatus'),
            array(&$result)
        );

        $this->engine->setOperation('--import', $arguments);
        $this->engine->setInput($input);
        $this->engine->run();

        $code = $this->engine->getErrorCode();

        switch ($code) {
            case self::ERROR_DUPLICATE_KEY:
            case self::ERROR_NONE:
                // ignore duplicate key import errors
                break;
            case self::ERROR_NO_DATA:
                throw new \Exception(
                    'No valid GPG key data found.',
                    $code
                );
            default:
                throw new \Exception(
                    'Unknown error importing GPG key.',
                    $code
                );
        }

        return $result;
    }

    /**
     * Exports a public key from the keyring.
     *
     * If more than one key fingerprint is available for the specified
     * <kbd>$keyId</kbd> (for example, if you use a non-unique uid) only the
     * first public key is exported.
     *
     * @param string $key   Either the full uid of the public key, the email
     *                      part of the uid of the public key or the key id of
     *                      the public key. For example,
     *                      "Test User (example) <test@example.com>",
     *                      "test@example.com" or a hexadecimal string.
     *
     * @return string the public key data.
     */
    public function exportPublicKey($key)
    {
        $fingerprint = null;
        $data = null;

        if ($key instanceof Key) {
            try {
                foreach ($key->getSubKeys() as $subKey) {
                    $data .= $this->export($subKey->getFingerprint());
                }

                return $data;
            } catch (\Exception $e) {
                return false;
            }
        } elseif ($key instanceof SubKey) {
            $fingerprint = $key->getFingerprint();
        } elseif (is_string($key)) {
            $fingerprint = $key;
        }

        if ($fingerprint === null) {
            return false;
        }

        try {
            return $this->export($fingerprint);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Exports a public key from the keyring.
     *
     * If more than one key fingerprint is available for the specified
     * <kbd>$keyId</kbd> (for example, if you use a non-unique uid) only the
     * first public key is exported.
     *
     * @param string $fingerprint either the full uid of the public key, the email
     *                            part of the uid of the public key or the key id of
     *                            the public key. For example,
     *                            "Test User (example) <test@example.com>",
     *                            "test@example.com" or a hexadecimal string.
     *
     * @return string the public key data.
     *
     * @throws Exception if a public key with the given
     *                   <kbd>$keyId</kbd> is not found.
     * @throws Exception if an unknown or unexpected error occurs.
     *                   Use the <kbd>debug</kbd> option and file a bug report if these
     *                   exceptions occur.
     */
    protected function export($fingerprint)
    {
        if ($fingerprint === null) {
            throw new \Exception(
                'Public key not found: '.$keyId,
                self::ERROR_KEY_NOT_FOUND
            );
        }

        $keyData   = '';
        $operation = '--export '.escapeshellarg($fingerprint);
        $arguments = ($this->armor) ? array('--armor') : array();

        $this->engine->reset();
        $this->engine->setOutput($keyData);
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        $code = $this->engine->getErrorCode();

        if ($code !== self::ERROR_NONE) {
            throw new \Exception(
                'Unknown error exporting public key. Please use the ',
                $code
            );
        }

        return $keyData;
    }

    /**
     * Deletes a public key from the keyring.
     *
     * If more than one key fingerprint is available for the specified
     * <kbd>$keyId</kbd> (for example, if you use a non-unique uid) only the
     * first public key is deleted.
     *
     * The private key must be deleted first or an exception will be thrown.
     * See {@link Crypt_GPG::deletePrivateKey()}.
     *
     * @param string $keyId either the full uid of the public key, the email
     *                      part of the uid of the public key or the key id of
     *                      the public key. For example,
     *                      "Test User (example) <test@example.com>",
     *                      "test@example.com" or a hexadecimal string.
     */
    public function deletePublicKey($key)
    {
        if ($key instanceof Key) {
            try {
                foreach ($key->getSubKeys() as $subKey) {
                    $data .= $this->deleteKey($subKey->getFingerprint());
                }

                return $data;
            } catch (\Exception $e) {
                return false;
            }
        } elseif ($key instanceof SubKey) {
            $fingerprint = $key->getFingerprint();
        } elseif (is_string($key)) {
            $fingerprint = $key;
        }

        if ($fingerprint === null) {
            return false;
        }
        try {
            $this->deleteKey($fingerprint);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Deletes a private key from the keyring.
     *
     * If more than one key fingerprint is available for the specified
     * <kbd>$keyId</kbd> (for example, if you use a non-unique uid) only the
     * first private key is deleted.
     *
     * Calls GPG with the <kbd>--delete-secret-key</kbd> command.
     *
     * @param string $keyId either the full uid of the private key, the email
     *                      part of the uid of the private key or the key id of
     *                      the private key. For example,
     *                      "Test User (example) <test@example.com>",
     *                      "test@example.com" or a hexadecimal string.
     *
     * @throws Crypt_GPG_KeyNotFoundException if a private key with the given
     *                                        <kbd>$keyId</kbd> is not found.
     * @throws Crypt_GPG_Exception            if an unknown or unexpected error occurs.
     *                                        Use the <kbd>debug</kbd> option and file a bug report if these
     *                                        exceptions occur.
     */
    public function deletePrivateKey($key)
    {
        if ($key instanceof Key) {
            try {
                foreach ($key->getSubKeys() as $subKey) {
                    $data .= $this->deleteKey($subKey->getFingerprint(), true);
                }

                return $data;
            } catch (\Exception $e) {
                return false;
            }
        } elseif ($key instanceof SubKey) {
            $fingerprint = $key->getFingerprint();
        } elseif (is_string($key)) {
            $fingerprint = $key;
        }

        if ($fingerprint === null) {
            return false;
        }
        try {
            $this->deleteKey($fingerprint, true);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Deletes a private key from the keyring.
     *
     * @param string $keyId either the full uid of the private key, the email
     *                      part of the uid of the private key or the key id of
     *                      the private key. For example,
     *                      "Test User (example) <test@example.com>",
     *                      "test@example.com" or a hexadecimal string.
     *
     * @param bool $allowprivate              determine if private key should be deleted as well
     *
     * @throws Exception                      if a private key with the given
     *                                        <kbd>$keyId</kbd> is not found.
     * @throws Exception                      if an unknown or unexpected error occurs.
     *                                        Use the <kbd>debug</kbd> option and file a bug report if these
     *                                        exceptions occur.
     */
    protected function deleteKey($keyId, $allowprivate = false)
    {
        if ($keyId === null) {
            throw new \Exception(
                'Private key not found: '.$keyId,
                self::ERROR_KEY_NOT_FOUND
            );
        }

        $keyId = $this->getFingerprint($keyId);

        if ($allowprivate) {
            //$operation = '--delete-secret-key '.escapeshellarg($keyId);
            $operation = '--delete-secret-and-public-key '.escapeshellarg($keyId);
        } else {
            $operation = '--delete-key '.escapeshellarg($keyId);
        }

        $arguments = array(
            '--batch',
            '--yes',
        );

        $this->engine->reset();
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        $code = $this->engine->getErrorCode();

        switch ($code) {
            case self::ERROR_NONE:
                break;
            case self::ERROR_KEY_NOT_FOUND:
                throw new \Exception(
                    'Private key not found: '.$keyId,
                    $code
                );
            default:
                throw new \Exception(
                    'Unknown error deleting private key.',
                    $code
                );
        }
    }


    /**
     * Gets a key fingerprint from the keyring.
     *
     * If more than one key fingerprint is available (for example, if you use
     * a non-unique user id) only the first key fingerprint is returned.
     *
     * Calls the GPG <kbd>--list-keys</kbd> command with the
     * <kbd>--with-fingerprint</kbd> option to retrieve a public key
     * fingerprint.
     *
     * @param string  $keyId  either the full user id of the key, the email
     *                        part of the user id of the key, or the key id of
     *                        the key. For example,
     *                        "Test User (example) <test@example.com>",
     *                        "test@example.com" or a hexadecimal string.
     * @param integer $format optional. How the fingerprint should be formatted.
     *                        Use {@link Crypt_GPG::FORMAT_X509} for X.509
     *                        certificate format,
     *                        {@link Crypt_GPG::FORMAT_CANONICAL} for the format
     *                        used by GnuPG output and
     *                        {@link Crypt_GPG::FORMAT_NONE} for no formatting.
     *                        Defaults to <code>Crypt_GPG::FORMAT_NONE</code>.
     *
     * @return string the fingerprint of the key, or null if no fingerprint
     *                is found for the given <kbd>$keyId</kbd>.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *                             Use the <kbd>debug</kbd> option and file a bug report if these
     *                             exceptions occur.
     */
    public function getFingerprint($keyId, $format = self::FORMAT_NONE)
    {
        $output    = '';
        $operation = '--list-keys '.escapeshellarg($keyId);
        $arguments = array(
            '--with-colons',
            '--with-fingerprint',
        );

        $this->engine->reset();
        $this->engine->setOutput($output);
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        $code = $this->engine->getErrorCode();

        switch ($code) {
        case self::ERROR_NONE:
        case self::ERROR_KEY_NOT_FOUND:
            // ignore not found key errors
            break;
        default:
            throw new \Exception(
                'Unknown error getting key fingerprint.',
                $code
            );
        }

        $fingerprint = null;

        $lines = explode(PHP_EOL, $output);
        foreach ($lines as $line) {
            if (substr($line, 0, 3) == 'fpr') {
                $lineExp     = explode(':', $line);
                $fingerprint = $lineExp[9];

                switch ($format) {
                    case self::FORMAT_CANONICAL:
                        $fingerprintExp = str_split($fingerprint, 4);
                        $format         = '%s %s %s %s %s  %s %s %s %s %s';
                        $fingerprint    = vsprintf($format, $fingerprintExp);
                        break;

                    case self::FORMAT_X509:
                        $fingerprintExp = str_split($fingerprint, 2);
                        $fingerprint    = implode(':', $fingerprintExp);
                        break;
                }

                break;
            }
        }

        return $fingerprint;
    }

    /**
     * Encrypts string data.
     *
     * Data is ASCII armored by default but may optionally be returned as
     * binary.
     *
     * @param string  $data  the data to be encrypted.
     *
     * @return string the encrypted data.
     */
    public function encrypt($data)
    {
        try {
            return $this->_encrypt($data);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Encrypts data.
     *
     * @param string  $data       the data to encrypt.
     *
     * @return string             string containing the encrypted data is returned.
     *
     * @throws Exception                      if no encryption key is specified.
     *                                        See {@link Crypt_GPG::addEncryptKey()}.
     * @throws Exception                      if the output file is not writeable or
     *                                        if the input file is not readable.
     * @throws Exception                      if an unknown or unexpected error occurs.
     *                                        Use the <kbd>debug</kbd> option and file a bug report if these
     *                                        exceptions occur.
     */
    protected function _encrypt($data)
    {
        if (count($this->encryptKeys) === 0) {
            throw new \Exception(
                'No encryption keys specified.'
            );
        }

        $input = strval($data);
        $output = '';

        $arguments = ($this->armor) ? array('--armor') : array();
        foreach ($this->encryptKeys as $key) {
            $arguments[] = '--recipient '.escapeshellarg($key['fingerprint']);
        }

        $this->engine->reset();
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->setOperation('--encrypt', $arguments);
        $this->engine->run();

        $code = $this->engine->getErrorCode();

        if ($code !== self::ERROR_NONE) {
            throw new \Exception(
                'Unknown error encrypting data.',
                $code
            );
        }

        return $output;
    }

    /**
     * Encrypts and signs data.
     *
     * Data is encrypted and signed in a single pass.
     *
     * NOTE: Until GnuPG version 1.4.10, it was not possible to verify
     * encrypted-signed data without decrypting it at the same time. If you try
     * to use {@link Crypt_GPG::verify()} method on encrypted-signed data with
     * earlier GnuPG versions, you will get an error. Please use
     * {@link Crypt_GPG::decryptAndVerify()} to verify encrypted-signed data.
     *
     * @param string  $data  the data to be encrypted and signed.
     *
     * @return string the encrypted signed data.
     */
    public function encryptAndSign($data)
    {
        try {
            return $this->_encryptAndSign($data, $armor);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Encrypts and signs data.
     *
     * @param string  $data       the data to be encrypted and signed.
     * @param boolean $isFile     whether or not the data is a filename.
     * @param string  $outputFile the name of the file in which the encrypted,
     *                            signed data should be stored. If null, the
     *                            encrypted, signed data is returned as a
     *                            string.
     * @param boolean $armor      if true, ASCII armored data is returned;
     *                            otherwise, binary data is returned.
     *
     * @return void|string if the <kbd>$outputFile</kbd> parameter is null, a
     *                     string containing the encrypted, signed data is
     *                     returned.
     *
     * @throws Crypt_GPG_KeyNotFoundException   if no encryption key is specified
     *                                          or if no signing key is specified. See
     *                                          {@link Crypt_GPG::addEncryptKey()} and
     *                                          {@link Crypt_GPG::addSignKey()}.
     * @throws Crypt_GPG_BadPassphraseException if a specified passphrase is
     *                                          incorrect or if a required passphrase is not specified.
     * @throws Crypt_GPG_FileException          if the output file is not writeable or
     *                                          if the input file is not readable.
     * @throws Crypt_GPG_Exception              if an unknown or unexpected error occurs.
     *                                          Use the <kbd>debug</kbd> option and file a bug report if these
     *                                          exceptions occur.
     */
    protected function _encryptAndSign($data)
    {
        if (count($this->signKeys) === 0) {
            throw new \Exception(
                'No signing keys specified.'
            );
        }

        if (count($this->encryptKeys) === 0) {
            throw new \Exception(
                'No encryption keys specified.'
            );
        }

        $input = strval($data);
        $output = '';

        $arguments  = ($this->armor) ? array('--armor') : array();

        foreach ($this->signKeys as $key) {
            $arguments[] = '--local-user '.
                escapeshellarg($key['fingerprint']);
        }

        // If using gpg-agent, set the sign pins used by the pinentry
        $this->_setPinEntryEnv($this->signKeys);

        foreach ($this->encryptKeys as $key) {
            $arguments[] = '--recipient '.escapeshellarg($key['fingerprint']);
        }

        $this->engine->reset();
        $this->engine->addStatusHandler(array($this, 'handleSignStatus'));
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->setOperation('--encrypt --sign', $arguments);
        $this->engine->run();

        $code = $this->engine->getErrorCode();

        switch ($code) {
            case self::ERROR_NONE:
                break;
            case self::ERROR_KEY_NOT_FOUND:
                throw new \Exception(
                    'Cannot sign encrypted data. Private key not found. Import '.
                    'the private key before trying to sign the encrypted data.',
                    $code
                );
            case self::ERROR_BAD_PASSPHRASE:
                throw new \Exception(
                    'Cannot sign encrypted data. Incorrect passphrase provided.',
                    $code
                );
            case self::ERROR_MISSING_PASSPHRASE:
                throw new \Exception(
                    'Cannot sign encrypted data. No passphrase provided.',
                    $code
                );
            default:
                throw new \Exception(
                    'Unknown error encrypting and signing data.',
                    $code
                );
        }

        return $output;
    }

    /**
     * Decrypts string data.
     *
     * This method assumes the required private key is available in the keyring
     * and throws an exception if the private key is not available. To add a
     * private key to the keyring, use the {@link Crypt_GPG::importKey()} or
     * {@link Crypt_GPG::importKeyFile()} methods.
     *
     * @param string $encryptedData the data to be decrypted.
     *
     * @return string the decrypted data.
     */
    public function decrypt($encryptedData)
    {
        try {
            return $this->_decrypt($encryptedData);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Decrypts data.
     *
     * @param string  $data       the data to be decrypted.
     *
     * @return string      a string containing the decrypted data is returned.
     *
     * @throws Exception                        if the private key needed to
     *                                          decrypt the data is not in the user's keyring.
     * @throws Exception                        if specified data does not contain
     *                                          GPG encrypted data.
     * @throws Exception                        if a required passphrase is
     *                                          incorrect or if a required passphrase is not specified. See
     *                                          {@link Crypt_GPG::addDecryptKey()}.
     * @throws Exception                        if an unknown or unexpected error occurs.
     *                                          Use the <kbd>debug</kbd> option and file a bug report if these
     *                                          exceptions occur.
     */
    protected function _decrypt($data)
    {
        $input = strval($data);
        if ($input == '') {
            throw new \Exception(
                'Cannot decrypt data. No PGP encrypted data was found in '.
                'the provided data.',
                self::ERROR_NO_DATA
            );
        }

        $output = '';

        $handler = new DecryptStatusHandler(
            $this->engine,
            $this->decryptKeys
        );

        // If using gpg-agent, set the decrypt pins used by the pinentry
        $this->_setPinEntryEnv($this->decryptKeys);

        $this->engine->reset();
        $this->engine->addStatusHandler(array($handler, 'handle'));
        $this->engine->setOperation('--decrypt');
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->run();

        // if there was any problem decrypting the data, the handler will
        // deal with it here.
        $handler->throwException();

        return $output;
    }

    /**
     * Decrypts and verifies string data.
     *
     * @param string $encryptedData the encrypted, signed data to be decrypted
     *                              and verified.
     *
     * @return Verificaction
     */
    public function decryptAndVerify($encryptedData)
    {
        try {
            return $this->_decryptAndVerify($encryptedData);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Decrypts and verifies encrypted, signed data.
     *
     * @param string  $data       the encrypted signed data to be decrypted and
     *                            verified.
     *
     * @return Verification
     *
     * @throws Exception                        if the private key needed to
     *                                          decrypt the data is not in the user's keyring or it the public
     *                                          key needed for verification is not in the user's keyring.
     * @throws Exception                       if specified data does not contain
     *                                          GPG signed, encrypted data.
     * @throws Exception                        if a required passphrase is
     *                                          incorrect or if a required passphrase is not specified. See
     *                                          {@link Crypt_GPG::addDecryptKey()}.
     * @throws Exception                        if the output file is not writeable or
     *                                          if the input file is not readable.
     * @throws Exception                        if an unknown or unexpected error occurs.
     *                                          Use the <kbd>debug</kbd> option and file a bug report if these
     *                                          exceptions occur.
     *
     * @see Crypt_GPG_Signature
     */
    protected function _decryptAndVerify($data)
    {
        $input = strval($data);
        if ($input == '') {
            throw new \Exception(
                'No valid encrypted signed data found.',
                self::ERROR_NO_DATA
            );
        }

        $output = '';

        $verifyHandler = new VerifyStatusHandler();

        $decryptHandler = new DecryptStatusHandler(
            $this->engine,
            $this->decryptKeys
        );

        // If using gpg-agent, set the decrypt pins used by the pinentry
        $this->_setPinEntryEnv($this->decryptKeys);

        $this->engine->reset();
        $this->engine->addStatusHandler(array($verifyHandler, 'handle'));
        $this->engine->addStatusHandler(array($decryptHandler, 'handle'));
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->setOperation('--decrypt');
        $this->engine->run();

        $return = array(
            'data'       => null,
            'signatures' => $verifyHandler->getSignatures(),
        );

        // if there was any problem decrypting the data, the handler will
        // deal with it here.
        try {
            $decryptHandler->throwException();
        } catch (\Exception $e) {
            throw $e;
        }

        $result = new \PhpGpg\Verification\Verification();
        $result->setData($output);
        foreach ($return['signatures'] as $signature) {
            $result->addSignature($signature);
        }

        return $result;
    }

    /**
     * Signs data.
     *
     * Data may be signed using any one of the three available signing modes:
     * - {@link Crypt_GPG::SIGN_MODE_NORMAL}
     * - {@link Crypt_GPG::SIGN_MODE_CLEAR}
     * - {@link Crypt_GPG::SIGN_MODE_DETACHED}
     *
     * @param string  $data     the data to be signed.
     * @param boolean $mode     optional. The data signing mode to use. Should
     *                          be one of {@link Crypt_GPG::SIGN_MODE_NORMAL},
     *                          {@link Crypt_GPG::SIGN_MODE_CLEAR} or
     *                          {@link Crypt_GPG::SIGN_MODE_DETACHED}. If not
     *                          specified, defaults to
     *                          <kbd>Crypt_GPG::SIGN_MODE_NORMAL</kbd>.
     * @param boolean $armor    optional. If true, ASCII armored data is
     *                          returned; otherwise, binary data is returned.
     *                          Defaults to true. This has no effect if the
     *                          mode <kbd>Crypt_GPG::SIGN_MODE_CLEAR</kbd> is
     *                          used.
     * @param boolean $textmode optional. If true, line-breaks in signed data
     *                          are normalized. Use this option when signing
     *                          e-mail, or for greater compatibility between
     *                          systems with different line-break formats.
     *                          Defaults to false. This has no effect if the
     *                          mode <kbd>Crypt_GPG::SIGN_MODE_CLEAR</kbd> is
     *                          used as clear-signing always uses textmode.
     *
     * @return string the signed data, or the signature data if a detached
     *                signature is requested.
     *
     * @throws Crypt_GPG_KeyNotFoundException   if no signing key is specified.
     *                                          See {@link Crypt_GPG::addSignKey()}.
     * @throws Crypt_GPG_BadPassphraseException if a specified passphrase is
     *                                          incorrect or if a required passphrase is not specified.
     * @throws Crypt_GPG_Exception              if an unknown or unexpected error occurs.
     *                                          Use the <kbd>debug</kbd> option and file a bug report if these
     *                                          exceptions occur.
     */
    public function sign($data, $mode = PhpGpg::SIG_MODE_CLEAR)
    {
        try {
            return $this->_sign($data, $mode);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Signs data.
     *
     * @param string  $data       the data to be signed.
     * @param boolean $mode       the data signing mode to use. Should be one of
     *                            {@link Crypt_GPG::SIGN_MODE_NORMAL},
     *                            {@link Crypt_GPG::SIGN_MODE_CLEAR} or
     *                            {@link Crypt_GPG::SIGN_MODE_DETACHED}.
     * @return string             a string containing the signed data (or the signature
     *                            data if a detached signature is requested) is
     *                            returned.
     *
     * @throws Exception                        if no signing key is specified.
     * @throws Exception                        if a specified passphrase is
     *                                          incorrect or if a required passphrase is not specified.
     * @throws Exception                        if the output file is not writeable or
     *                                          if the input file is not readable.
     * @throws Exception                        if an unknown or unexpected error occurs.
     *                                          Use the <kbd>debug</kbd> option and file a bug report if these
     *                                          exceptions occur.
     */
    protected function _sign($data, $mode)
    {
        if (count($this->signKeys) === 0) {
            throw new \Exception(
                'No signing keys specified.'
            );
        }

        $input = strval($data);
        $output = '';

        switch ($mode) {
        case PhpGpg::SIG_MODE_DETACHED:
            $operation = '--detach-sign';
            break;
        case PhpGpg::SIG_MODE_CLEAR:
            $operation = '--clearsign';
            break;
        case PhpGpg::SIG_MODE_NORMAL:
        default:
            $operation = '--sign';
            break;
        }

        $arguments  = array();

        if ($this->armor) {
            $arguments[] = '--armor';
        }

        //ignore for now
        if ($textmode) {
            $arguments[] = '--textmode';
        }

        foreach ($this->signKeys as $key) {
            $arguments[] = '--local-user '.
                escapeshellarg($key['fingerprint']);
        }

        // If using gpg-agent, set the sign pins used by the pinentry
        $this->_setPinEntryEnv($this->signKeys);

        $this->engine->reset();
        $this->engine->addStatusHandler(array($this, 'handleSignStatus'));
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        $code = $this->engine->getErrorCode();

        switch ($code) {
            case self::ERROR_NONE:
                break;
            case self::ERROR_KEY_NOT_FOUND:
                throw new \Exception(
                    'Cannot sign data. Private key not found. Import the '.
                    'private key before trying to sign data.',
                    $code
                );
            case self::ERROR_BAD_PASSPHRASE:
                throw new \Exception(
                    'Cannot sign data. Incorrect passphrase provided.',
                    $code
                );
            case self::ERROR_MISSING_PASSPHRASE:
                throw new \Exception(
                    'Cannot sign data. No passphrase provided.',
                    $code
                );
            default:
                throw new \Exception(
                    'Unknown error signing data.',
                    $code
                );
        }

        return $output;
    }

    /**
     * Verifies signed data.
     *
     * The {@link Crypt_GPG::decrypt()} method may be used to get the original
     * message if the signed data is not clearsigned and does not use a
     * detached signature.
     *
     * @param string $signedData the signed data to be verified.
     * @param string $signature  optional. If verifying data signed using a
     *                           detached signature, this must be the detached
     *                           signature data. The data that was signed is
     *                           specified in <kbd>$signedData</kbd>.
     *
     * @return Verification
     */
    public function verify($signedData, $signature = '')
    {
        try {
            return $this->_verify($signedData, $signature);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Verifies data.
     *
     * @param string  $data      the signed data to be verified.
     * @param string  $signature if verifying a file signed using a detached
     *                           signature, this must be the detached signature
     *                           data. Otherwise, specify ''.
     *
     * @return Verification
     *
     * @throws Exception                 if the provided data is not signed
     *                                   data.
     * @throws Exception                 if the input file is not readable.
     * @throws Exception                 if an unknown or unexpected error occurs.
     *                                   Use the <kbd>debug</kbd> option and file a bug report if these
     *                                   exceptions occur.
     */
    protected function _verify($data, $signature)
    {
        if ($signature == '') {
            $operation = '--verify';
            $arguments = array();
        } else {
            // Signed data goes in FD_MESSAGE, detached signature data goes in
            // FD_INPUT.
            $operation = '--verify - "-&'.Cli\Engine::FD_MESSAGE.'"';
            $arguments = array('--enable-special-filenames');
        }

        $handler = new VerifyStatusHandler();

        $input = strval($data);
        if ($input == '') {
            throw new \Exception(
                'No valid signature data found.',
                self::ERROR_NO_DATA
            );
        }

        $this->engine->reset();
        $this->engine->addStatusHandler(array($handler, 'handle'));

        if ($signature == '') {
            // signed or clearsigned data
            $this->engine->setInput($input);
        } else {
            // detached signature
            $this->engine->setInput($signature);
            $this->engine->setMessage($input);
        }

        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        $code = $this->engine->getErrorCode();

        switch ($code) {
        case self::ERROR_NONE:
        case self::ERROR_BAD_SIGNATURE:
            break;
        case self::ERROR_NO_DATA:
            throw new \Exception(
                'No valid signature data found.',
                $code
            );
        case self::ERROR_KEY_NOT_FOUND:
            throw new \Exception(
                'Public key required for data verification not in keyring.',
                $code
            );
        default:
            throw new \Exception(
                'Unknown error validating signature details.',
                $code
            );
        }

        //TODO: this needs fixing, should return a Verification object
        return $handler->getSignatures();
    }

    /**
     * Adds a key to use for decryption.
     *
     * @param mixed  $key        the key to use. This may be a key identifier,
     *                           user id, fingerprint, {@link Crypt_GPG_Key} or
     *                           {@link Crypt_GPG_SubKey}. The key must be able
     *                           to encrypt.
     * @param string $passphrase optional. The passphrase of the key required
     *                           for decryption.
     *
     * @return bool
     */
    public function addDecryptKey($key, $passphrase = null)
    {
        try {
            $this->_addKey($this->decryptKeys, true, false, $key, $passphrase);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Adds a key to use for encryption.
     *
     * @param mixed $key the key to use. This may be a key identifier, user id
     *                   user id, fingerprint, {@link Crypt_GPG_Key} or
     *                   {@link Crypt_GPG_SubKey}. The key must be able to
     *                   encrypt.
     *
     * @return bool
     */
    public function addEncryptKey($key)
    {
        try {
            $this->_addKey($this->encryptKeys, true, false, $key);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Adds a key to use for signing.
     *
     * @param mixed  $key        the key to use. This may be a key identifier,
     *                           user id, fingerprint, {@link Crypt_GPG_Key} or
     *                           {@link Crypt_GPG_SubKey}. The key must be able
     *                           to sign.
     * @param string $passphrase optional. The passphrase of the key required
     *                           for signing.
     */
    public function addSignKey($key, $passphrase = null)
    {
        try {
            $this->_addKey($this->signKeys, false, true, $key, $passphrase);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Clears all decryption keys.
     *
     * @return bool
     */
    public function clearDecryptKeys()
    {
        $this->decryptKeys = array();

        return true;
    }

    /**
     * Clears all encryption keys.
     *
     * @return bool
     */
    public function clearEncryptKeys()
    {
        $this->encryptKeys = array();

        return true;
    }

    /**
     * Clears all signing keys.
     *
     * @return bool
     */
    public function clearSignKeys()
    {
        $this->signKeys = array();

        return true;
    }

    /**
     * Handles the status output from GPG for the sign operation.
     *
     * This method is responsible for sending the passphrase commands when
     * required by the {@link Crypt_GPG::sign()} method. See <b>doc/DETAILS</b>
     * in the {@link http://www.gnupg.org/download/ GPG distribution} for
     * detailed information on GPG's status output.
     *
     * @param string $line the status line to handle.
     */
    public function handleSignStatus($line)
    {
        $tokens = explode(' ', $line);
        switch ($tokens[0]) {
        case 'NEED_PASSPHRASE':
            $subKeyId = $tokens[1];
            if (array_key_exists($subKeyId, $this->signKeys)) {
                $passphrase = $this->signKeys[$subKeyId]['passphrase'];
                $this->engine->sendCommand($passphrase);
            } else {
                $this->engine->sendCommand('');
            }
            break;
        }
    }

    /**
     * Handles the status output from GPG for the import operation.
     *
     * This method is responsible for building the result array that is
     * returned from the {@link Crypt_GPG::importKey()} method. See
     * <b>doc/DETAILS</b> in the
     * {@link http://www.gnupg.org/download/ GPG distribution} for detailed
     * information on GPG's status output.
     *
     * @param string $line    the status line to handle.
     * @param array  &$result the current result array being processed.
     */
    public function handleImportKeyStatus($line, array &$result)
    {
        $tokens = explode(' ', $line);
        switch ($tokens[0]) {
        case 'IMPORT_OK':
            $result['fingerprint'] = $tokens[2];
            break;

        case 'IMPORT_RES':
            $result['public_imported']   = intval($tokens[3]);
            $result['public_unchanged']  = intval($tokens[5]);
            $result['private_imported']  = intval($tokens[11]);
            $result['private_unchanged'] = intval($tokens[12]);
            break;
        }
    }

    /**
     * Adds a key to one of the internal key arrays.
     *
     * This handles resolving full key objects from the provided
     * <kbd>$key</kbd> value.
     *
     * @param array   &$array     the array to which the key should be added.
     * @param boolean $encrypt    whether or not the key must be able to
     *                            encrypt.
     * @param boolean $sign       whether or not the key must be able to sign.
     * @param mixed   $key        the key to add. This may be a key identifier,
     *                            user id, fingerprint, {@link Crypt_GPG_Key} or
     *                            {@link Crypt_GPG_SubKey}.
     * @param string  $passphrase optional. The passphrase associated with the
     *                            key.
     *
     *
     * @sensitive $passphrase
     */
    protected function _addKey(array &$array, $encrypt, $sign, $key,
        $passphrase = null
    ) {
        $subKeys = array();

        if (is_scalar($key)) {
            $keys = $this->getKeys($key);
            if (count($keys) == 0) {
                throw new \Exception(
                    'Key "'.$key.'" not found.',
                    0
                );
            }
            $key = $keys[0];
        }

        if ($key instanceof Key) {
            if ($encrypt && !$key->canEncrypt()) {
                throw new \InvalidArgumentException(
                    'Key "'.$key.'" cannot encrypt.'
                );
            }

            if ($sign && !$key->canSign()) {
                throw new \InvalidArgumentException(
                    'Key "'.$key.'" cannot sign.'
                );
            }

            foreach ($key->getSubKeys() as $subKey) {
                $canEncrypt = $subKey->canEncrypt();
                $canSign    = $subKey->canSign();
                if (($encrypt && $sign && $canEncrypt && $canSign)
                    || ($encrypt && !$sign && $canEncrypt)
                    || (!$encrypt && $sign && $canSign)
                ) {
                    // We add all subkeys that meet the requirements because we
                    // were not told which subkey is required.
                    $subKeys[] = $subKey;
                }
            }
        } elseif ($key instanceof SubKey) {
            $subKeys[] = $key;
        }

        if (count($subKeys) === 0) {
            throw new \InvalidArgumentException(
                'Key "'.$key.'" is not in a recognized format.'
            );
        }

        foreach ($subKeys as $subKey) {
            if ($encrypt && !$subKey->canEncrypt()) {
                throw new \InvalidArgumentException(
                    'Key "'.$key.'" cannot encrypt.'
                );
            }

            if ($sign && !$subKey->canSign()) {
                throw new \InvalidArgumentException(
                    'Key "'.$key.'" cannot sign.'
                );
            }

            $array[$subKey->getId()] = array(
                'fingerprint' => $subKey->getFingerprint(),
                'passphrase'  => $passphrase,
            );
        }
    }

    /**
     * Sets the PINENTRY_USER_DATA environment variable with the currently
     * added keys and passphrases.
     *
     * Keys and pasphrases are stored as an indexed array of associative
     * arrays that is JSON encoded to a flat string.
     *
     * For GnuPG 2.x this is how passphrases are passed. For GnuPG 1.x the
     * environment variable is set but not used.
     *
     * @param array $keys the internal key array to use.
     */
    protected function _setPinEntryEnv(array $keys)
    {
        $envKeys = array();
        foreach ($keys as $id => $key) {
            $envKeys[] = array(
                'keyId'       => $id,
                'fingerprint' => $key['fingerprint'],
                'passphrase'  => $key['passphrase'],
            );
        }
        $envKeys = json_encode($envKeys);
        $_ENV['PINENTRY_USER_DATA'] = $envKeys;
    }
}
