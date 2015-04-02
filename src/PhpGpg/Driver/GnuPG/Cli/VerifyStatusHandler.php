<?php
namespace PhpGpg\Driver\GnuPG\Cli;

use PhpGpg\Driver\GnuPG\Cli;
use PhpGpg\Signature\Signature;

class VerifyStatusHandler
{
    /**
     * The current signature id.
     *
     * Ths signature id is emitted by GPG before the new signature line so we
     * must remember it temporarily.
     *
     * @var string
     */
    protected $signatureId = '';

    /**
     * List of parsed {@link Crypt_GPG_Signature} objects.
     *
     * @var array
     */
    protected $signatures = array();

    /**
     * Array index of the current signature.
     *
     * @var integer
     */
    protected $index = -1;

    /**
     * Handles a status line.
     *
     * @param string $line the status line to handle.
     */
    public function handle($line)
    {
        $tokens = explode(' ', $line);
        switch ($tokens[0]) {
        case 'GOODSIG':
        case 'EXPSIG':
        case 'EXPKEYSIG':
        case 'REVKEYSIG':
        case 'BADSIG':
            $signature = new Signature();

            // if there was a signature id, set it on the new signature
            if ($this->signatureId != '') {
                //$signature->setId($this->signatureId);
                $this->signatureId = '';
            }

            // Detect whether fingerprint or key id was returned and set
            // signature values appropriately. Key ids are strings of either
            // 16 or 8 hexadecimal characters. Fingerprints are strings of 40
            // hexadecimal characters. The key id is the last 16 characters of
            // the key fingerprint.
            if (strlen($tokens[1]) > 16) {
                $signature->setFingerprint($tokens[1]);
                //$signature->setKeyId(substr($tokens[1], -16));
            } else {
                //$signature->setKeyId($tokens[1]);
            }

            // get user id string
            $string = implode(' ', array_splice($tokens, 2));
            $string = rawurldecode($string);

            //$signature->setUserId(Cli::parseUserIdLine($string));

            $this->index++;
            $this->signatures[$this->index] = $signature;
            break;

        case 'ERRSIG':
            $signature = new Signature();

            // if there was a signature id, set it on the new signature
            if ($this->signatureId != '') {
                //$signature->setId($this->signatureId);
                $this->signatureId = '';
            }

            // Detect whether fingerprint or key id was returned and set
            // signature values appropriately. Key ids are strings of either
            // 16 or 8 hexadecimal characters. Fingerprints are strings of 40
            // hexadecimal characters. The key id is the last 16 characters of
            // the key fingerprint.
            if (strlen($tokens[1]) > 16) {
                $signature->setFingerprint($tokens[1]);
                //$signature->setKeyId(substr($tokens[1], -16));
            } else {
                //$signature->setKeyId($tokens[1]);
            }

            $this->index++;
            $this->signatures[$this->index] = $signature;

            break;

        case 'VALIDSIG':
            if (!array_key_exists($this->index, $this->signatures)) {
                break;
            }

            $signature = $this->signatures[$this->index];

            //$signature->setValid(true);
            $signature->setFingerprint($tokens[1]);

            if (strpos($tokens[3], 'T') === false) {
                $signature->setCreationDate($tokens[3]);
            } else {
                $signature->setCreationDate(strtotime($tokens[3]));
            }

            if (array_key_exists(4, $tokens)) {
                if (strpos($tokens[4], 'T') === false) {
                    //$signature->setExpirationDate($tokens[4]);
                } else {
                    //$signature->setExpirationDate(strtotime($tokens[4]));
                }
            }

            break;

        case 'SIG_ID':
            // note: signature id comes before new signature line and may not
            // exist for some signature types
            $this->signatureId = $tokens[1];
            break;
        }
    }

    /**
     * Gets the {@link Crypt_GPG_Signature} objects parsed by this handler.
     *
     * @return array the signature objects parsed by this handler.
     */
    public function getSignatures()
    {
        return $this->signatures;
    }
}
