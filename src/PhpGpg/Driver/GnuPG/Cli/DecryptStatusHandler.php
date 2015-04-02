<?php
namespace PhpGpg\Driver\GnuPG\Cli;

use PhpGpg\Driver\GnuPG\Cli;

class DecryptStatusHandler
{
    // {{{ protected properties

    /**
     * Keys used to decrypt.
     *
     * The array is of the form:
     * <code>
     * array(
     *   $key_id => array(
     *     'fingerprint' => $fingerprint,
     *     'passphrase'  => $passphrase
     *   )
     * );
     * </code>
     *
     * @var array
     */
    protected $keys = array();

    /**
     * Engine used to which passphrases are passed.
     *
     * @var Crypt_GPG_Engine
     */
    protected $engine = null;

    /**
     * The id of the current sub-key used for decryption.
     *
     * @var string
     */
    protected $currentSubKey = '';

    /**
     * Whether or not decryption succeeded.
     *
     * If the message is only signed (compressed) and not encrypted, this is
     * always true. If the message is encrypted, this flag is set to false
     * until we know the decryption succeeded.
     *
     * @var boolean
     */
    protected $decryptionOkay = true;

    /**
     * Whether or not there was no data for decryption.
     *
     * @var boolean
     */
    protected $noData = false;

    /**
     * Keys for which the passhprase is missing.
     *
     * This contains primary user ids indexed by sub-key id and is used to
     * create helpful exception messages.
     *
     * @var array
     */
    protected $missingPassphrases = array();

    /**
     * Keys for which the passhprase is incorrect.
     *
     * This contains primary user ids indexed by sub-key id and is used to
     * create helpful exception messages.
     *
     * @var array
     */
    protected $badPassphrases = array();

    /**
     * Keys that can be used to decrypt the data but are missing from the
     * keychain.
     *
     * This is an array with both the key and value being the sub-key id of
     * the missing keys.
     *
     * @var array
     */
    protected $missingKeys = array();

    // }}}
    // {{{ __construct()

    /**
     * Creates a new decryption status handler.
     *
     * @param Crypt_GPG_Engine $engine the GPG engine to which passphrases are
     *                                 passed.
     * @param array            $keys   the decryption keys to use.
     */
    public function __construct(Engine $engine, array $keys)
    {
        $this->engine = $engine;
        $this->keys   = $keys;
    }

    // }}}
    // {{{ handle()

    /**
     * Handles a status line.
     *
     * @param string $line the status line to handle.
     */
    public function handle($line)
    {
        $tokens = explode(' ', $line);
        switch ($tokens[0]) {
        case 'ENC_TO':
            // Now we know the message is encrypted. Set flag to check if
            // decryption succeeded.
            $this->decryptionOkay = false;

            // this is the new key message
            $this->currentSubKeyId = $tokens[1];
            break;

        case 'NEED_PASSPHRASE':
            // send passphrase to the GPG engine
            $subKeyId = $tokens[1];
            if (array_key_exists($subKeyId, $this->keys)) {
                $passphrase = $this->keys[$subKeyId]['passphrase'];
                $this->engine->sendCommand($passphrase);
            } else {
                $this->engine->sendCommand('');
            }
            break;

        case 'USERID_HINT':
            // remember the user id for pretty exception messages
            $this->badPassphrases[$tokens[1]]
                = implode(' ', array_splice($tokens, 2));

            break;

        case 'GOOD_PASSPHRASE':
            // if we got a good passphrase, remove the key from the list of
            // bad passphrases.
            unset($this->badPassphrases[$this->currentSubKeyId]);
            break;

        case 'MISSING_PASSPHRASE':
            $this->missingPassphrases[$this->currentSubKeyId]
                = $this->currentSubKeyId;

            break;

        case 'NO_SECKEY':
            // note: this message is also received if there are multiple
            // recipients and a previous key had a correct passphrase.
            $this->missingKeys[$tokens[1]] = $tokens[1];
            break;

        case 'NODATA':
            $this->noData = true;
            break;

        case 'DECRYPTION_OKAY':
            // If the message is encrypted, this is the all-clear signal.
            $this->decryptionOkay = true;
            break;
        }
    }

    // }}}
    // {{{ throwException()

    /**
     * Takes the final status of the decrypt operation and throws an
     * appropriate exception.
     *
     * If decryption was successful, no exception is thrown.
     *
     *
     * @throws Crypt_GPG_KeyNotFoundException   if the private key needed to
     *                                          decrypt the data is not in the user's keyring.
     * @throws Crypt_GPG_NoDataException        if specified data does not contain
     *                                          GPG encrypted data.
     * @throws Crypt_GPG_BadPassphraseException if a required passphrase is
     *                                          incorrect or if a required passphrase is not specified. See
     *                                          {@link Crypt_GPG::addDecryptKey()}.
     * @throws Crypt_GPG_Exception              if an unknown or unexpected error occurs.
     *                                          Use the <i>debug</i> option and file a bug report if these
     *                                          exceptions occur.
     */
    public function throwException()
    {
        $code = Cli::ERROR_NONE;

        if (!$this->decryptionOkay) {
            if (count($this->badPassphrases) > 0) {
                $code = Cli::ERROR_BAD_PASSPHRASE;
            } elseif (count($this->missingKeys) > 0) {
                $code = Cli::ERROR_KEY_NOT_FOUND;
            } else {
                $code = Cli::ERROR_UNKNOWN;
            }
        } elseif ($this->noData) {
            $code = Cli::ERROR_NO_DATA;
        }

        switch ($code) {
            case Cli::ERROR_NONE:
                break;

            case Cli::ERROR_KEY_NOT_FOUND:
                if (count($this->missingKeys) > 0) {
                    $keyId = reset($this->missingKeys);
                } else {
                    $keyId = '';
                }
                throw new \Exception(
                    'Cannot decrypt data. No suitable private key is in the '.
                    'keyring. Import a suitable private key before trying to '.
                    'decrypt this data.',
                    $code
                );
            case Cli::ERROR_BAD_PASSPHRASE:
                $badPassphrases = array_diff_key(
                    $this->badPassphrases,
                    $this->missingPassphrases
                );

                $missingPassphrases = array_intersect_key(
                    $this->badPassphrases,
                    $this->missingPassphrases
                );

                $message =  'Cannot decrypt data.';
                if (count($badPassphrases) > 0) {
                    $message = ' Incorrect passphrase provided for keys: "'.
                        implode('", "', $badPassphrases).'".';
                }
                if (count($missingPassphrases) > 0) {
                    $message = ' No passphrase provided for keys: "'.
                        implode('", "', $badPassphrases).'".';
                }

                throw new \Exception(
                    $message . $badPassphrases .$missingPassphrases,
                    $code
                );
            case Cli::ERROR_NO_DATA:
                throw new \Exception(
                    'Cannot decrypt data. No PGP encrypted data was found in '.
                    'the provided data.',
                    $code
                );
            default:
                throw new \Exception(
                    'Unknown error decrypting data.',
                    $code
                );
        }
    }

    // }}}
}
