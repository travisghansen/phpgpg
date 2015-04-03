<?php
namespace PhpGpg\Driver\GnuPG\Cli;

/**
 * A command-line dummy pinentry program for use with gpg-agent and Crypt_GPG.
 *
 * This pinentry receives passphrases through en environment variable and
 * automatically enters the PIN in response to gpg-agent requests. No user-
 * interaction required.
 *
 * Thie pinentry can be run independently for testing and debugging with the
 * following syntax:
 *
 * Usage:
 *   crypt-gpg-pinentry [options]
 *
 * Options:
 *   -l log, --log=log  Optional location to log pinentry activity.
 *   -v, --verbose      Sets verbosity level. Use multiples for more detail
 *                      (e.g. "-vv").
 *   -h, --help         show this help message and exit
 *   --version          show the program version and exit
 */
class PinEntry
{
    /**
     * Verbosity level for showing no output.
     */
    const VERBOSITY_NONE = 0;

    /**
     * Verbosity level for showing error output.
     */
    const VERBOSITY_ERRORS = 1;

    /**
     * Verbosity level for showing all output, including Assuan protocol
     * messages.
     */
    const VERBOSITY_ALL = 2;

    /**
     * Length of buffer for reading lines from the Assuan server.
     *
     * PHP reads 8192 bytes. If this is set to less than 8192, PHP reads 8192
     * and buffers the rest so we might as well just read 8192.
     *
     * Using values other than 8192 also triggers PHP bugs.
     *
     * @see http://bugs.php.net/bug.php?id=35224
     */
    const CHUNK_SIZE = 8192;

    /**
     * File handle for the input stream.
     *
     * @var resource
     */
    protected $stdin = null;

    /**
     * File handle for the output stream.
     *
     * @var resource
     */
    protected $stdout = null;

    /**
     * File handle for the log file if a log file is used.
     *
     * @var resource
     */
    protected $logFile = null;

    /**
     * Whether or not this pinentry is finished and is exiting.
     *
     * @var boolean
     */
    protected $moribund = false;

    /**
     * Verbosity level.
     *
     * One of:
     * - {@link PinEntry::VERBOSITY_NONE},
     * - {@link PinEntry::VERBOSITY_ERRORS}, or
     * - {@link PinEntry::VERBOSITY_ALL}
     *
     * @var integer
     */
    protected $verbosity = self::VERBOSITY_NONE;

    /**
     * PINs to be entered by this pinentry.
     *
     * An indexed array of associative arrays in the form:
     * <code>
     * <?php
     *   array(
     *     array(
     *       'keyId'      => $keyId,
     *       'passphrase' => $passphrase
     *     ),
     *     ...
     *   );
     * ?>
     * </code>
     *
     * This array is parsed from the environment variable
     * <kbd>PINENTRY_USER_DATA</kbd>.
     *
     * @var array
     *
     * @see Crypt_GPG_PinEntry::initPinsFromENV()
     */
    protected $pins = array();

    /**
     * PINs that have been tried for the current PIN.
     *
     * This is an associative array indexed by the key identifier with
     * values being the same as elements in the {@link Crypt_GPG_PinEntry::$pins}
     * array.
     *
     * @var array
     */
    protected $triedPins = array();

    /**
     * The PIN currently being requested by the Assuan server.
     *
     * If set, this is an associative array in the form:
     * <code>
     * <?php
     *   array(
     *     'keyId'  => $shortKeyId,
     *     'userId' => $userIdString
     *   );
     * ?>
     * </code>
     *
     * @var array|null
     */
    protected $currentPin = null;

    /**
     * Runs this pinentry.
     */
    public function __invoke()
    {
        $options = getopt("l:v", array('logs:', 'verbose'));
        $verbose_count = (count($options['v']) + count($options['verbose']));
        if ($verbose_count > self::VERBOSITY_ALL) {
            $verbose_count = self::VERBOSITY_ALL;
        }

        $logfile = (is_string($options['logs'])) ? $options['logs'] : null;
        if ($logfile === null) {
            $logfile = (is_string($options['l'])) ? $options['l'] : null;
        }

        //$logfile = '/tmp/pinentry.log';
        //$verbose_count = 3;

        try {
            $this->setVerbosity($verbose_count);
            $this->setLogFilename($logfile);

            $this->connect();
            $this->initPinsFromENV();

            while (($line = fgets($this->stdin, self::CHUNK_SIZE)) !== false) {
                $this->parseCommand(mb_substr($line, 0, -1, '8bit'));
                if ($this->moribund) {
                    break;
                }
            }

            $this->disconnect();
        } catch (\Exception $e) {
            $this->log($e->getMessage().PHP_EOL, self::VERBOSITY_ERRORS);
            $this->log($e->getTraceAsString().PHP_EOL, self::VERBOSITY_ERRORS);
            exit(1);
        }
    }

    /**
     * Sets the verbosity of logging for this pinentry.
     *
     * Verbosity levels are:
     *
     * - {@link PinEntry::VERBOSITY_NONE}   - no logging.
     * - {@link PinEntry::VERBOSITY_ERRORS} - log errors only.
     * - {@link PinEntry::VERBOSITY_ALL}    - log everything, including
     *                                        the assuan protocol.
     *
     * @param integer $verbosity the level of verbosity of this pinentry.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    public function setVerbosity($verbosity)
    {
        $this->verbosity = (integer) $verbosity;

        return $this;
    }

    /**
     * Sets the log file location.
     *
     * @param string $filename the new log filename to use. If an empty string
     *                         is used, file-based logging is disabled.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    public function setLogFilename($filename)
    {
        if (is_resource($this->logFile)) {
            fflush($this->logFile);
            fclose($this->logFile);
            $this->logFile = null;
        }

        if ($filename != '') {
            if (($this->logFile = fopen($filename, 'w')) === false) {
                $this->log(
                    'Unable to open log file "'.$filename.'" '
                    .'for writing.'.PHP_EOL,
                    self::VERBOSITY_ERRORS
                );
                exit(1);
            } else {
                stream_set_write_buffer($this->logFile, 0);
            }
        }

        return $this;
    }

    /**
     * Logs a message at the specified verbosity level.
     *
     * If a log file is used, the message is written to the log. Otherwise,
     * the message is sent to STDERR.
     *
     * @param string  $data  the message to log.
     * @param integer $level the verbosity level above which the message should
     *                       be logged.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function log($data, $level)
    {
        if ($this->verbosity >= $level) {
            if (is_resource($this->logFile)) {
                fwrite($this->logFile, $data);
                fflush($this->logFile);
            } else {
                fwrite(STDERR, $data);
            }
        }

        return $this;
    }

    /**
     * Connects this pinentry to the assuan server.
     *
     * Opens I/O streams and sends initial handshake.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function connect()
    {
        // Binary operations will not work on Windows with PHP < 5.2.6.
        $rb = (version_compare(PHP_VERSION, '5.2.6') < 0) ? 'r' : 'rb';
        $wb = (version_compare(PHP_VERSION, '5.2.6') < 0) ? 'w' : 'wb';

        $this->stdin  = fopen('php://stdin', $rb);
        $this->stdout = fopen('php://stdout', $wb);

        if (function_exists('stream_set_read_buffer')) {
            stream_set_read_buffer($this->stdin, 0);
        }
        stream_set_write_buffer($this->stdout, 0);

        // initial handshake
        $this->send($this->getOK('Crypt_GPG pinentry ready and waiting'));

        return $this;
    }

    /**
     * Parses an assuan command and performs the appropriate action.
     *
     * Documentation of the assuan commands for pinentry is limited to
     * non-existent. Most of these commands were taken from the C source code
     * to gpg-agent and pinentry.
     *
     * Additional context was provided by using strace -f when calling the
     * gpg-agent.
     *
     * @param string $line the assuan command line to parse
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function parseCommand($line)
    {
        $this->log('<- '.$line.PHP_EOL, self::VERBOSITY_ALL);

        $parts = explode(' ', $line, 2);

        $command = $parts[0];

        if (count($parts) === 2) {
            $data = $parts[1];
        } else {
            $data = null;
        }

        switch ($command) {
            case 'SETDESC':
                return $this->sendSetDescription($data);

            case 'SETPROMPT':
            case 'SETERROR':
            case 'SETOK':
            case 'SETNOTOK':
            case 'SETCANCEL':
            case 'SETQUALITYBAR':
            case 'SETQUALITYBAR_TT':
            case 'OPTION':
                return $this->sendNotImplementedOK();

            case 'MESSAGE':
                return $this->sendMessage();

            case 'CONFIRM':
                return $this->sendConfirm();

            case 'GETINFO':
                return $this->sendGetInfo($data);

            case 'GETPIN':
                return $this->sendGetPin($data);

            case 'RESET':
                return $this->sendReset();

            case 'BYE':
                return $this->sendBye();
        }
    }

    /**
     * Initializes the PINs to be entered by this pinentry from the environment
     * variable PINENTRY_USER_DATA.
     *
     * The PINs are parsed from a JSON-encoded string.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function initPinsFromENV()
    {
        if (($userData = getenv('PINENTRY_USER_DATA')) !== false) {
            $pins = json_decode($userData, true);
            if ($pins === null) {
                $this->log(
                    '-- failed to parse user data'.PHP_EOL,
                    self::VERBOSITY_ERRORS
                );
            } else {
                $this->pins = $pins;
                $this->log(
                    '-- got user data [not showing passphrases]'.PHP_EOL,
                    self::VERBOSITY_ALL
                );
            }
        }

        return $this;
    }

    /**
     * Disconnects this pinentry from the Assuan server.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function disconnect()
    {
        $this->log('-- disconnecting'.PHP_EOL, self::VERBOSITY_ALL);

        fflush($this->stdout);
        fclose($this->stdout);
        fclose($this->stdin);

        $this->stdin  = null;
        $this->stdout = null;

        $this->log('-- disconnected'.PHP_EOL, self::VERBOSITY_ALL);

        if (is_resource($this->logFile)) {
            fflush($this->logFile);
            fclose($this->logFile);
            $this->logFile = null;
        }

        return $this;
    }

    /**
     * Sends an OK response for a not implemented feature.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function sendNotImplementedOK()
    {
        return $this->send($this->getOK());
    }

    /**
     * Parses the currently requested key identifier and user identifier from
     * the description passed to this pinentry.
     *
     * @param string $text the raw description sent from gpg-agent.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function sendSetDescription($text)
    {
        $text = rawurldecode($text);
        $matches = array();
        // TODO: handle user id with quotation marks
        $exp = '/\n"(.+)"\n.*\sID ([A-Z0-9]+),\n/mu';
        if (preg_match($exp, $text, $matches) === 1) {
            $userId = $matches[1];
            $keyId  = $matches[2];

            // only reset tried pins for new requested pin
            if ($this->currentPin === null
                || $this->currentPin['keyId'] !== $keyId
            ) {
                $this->currentPin = array(
                    'userId' => $userId,
                    'keyId'  => $keyId,
                );
                $this->triedPins = array();
                $this->log(
                    '-- looking for PIN for '.$keyId.PHP_EOL,
                    self::VERBOSITY_ALL
                );
            }
        }

        return $this->send($this->getOK());
    }

    /**
     * Tells the assuan server the PIN entry was confirmed (not cancelled)
     * by pressing the fake 'close' button.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function sendConfirm()
    {
        return $this->sendButtonInfo('close');
    }

    /**
     * Tells the assuan server that any requested pop-up messages were confirmed
     * by pressing the fake 'close' button.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function sendMessage()
    {
        return $this->sendButtonInfo('close');
    }

    /**
     * Sends information about pressed buttons to the assuan server.
     *
     * This is used to fake a user-interface for this pinentry.
     *
     * @param string $text the button status to send.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function sendButtonInfo($text)
    {
        return $this->send('BUTTON_INFO '.$text."\n");
    }

    /**
     * Sends the PIN value for the currently requested key.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function sendGetPin()
    {
        $foundPin = '';

        if (is_array($this->currentPin)) {
            $keyIdLength = mb_strlen($this->currentPin['keyId'], '8bit');

            // search for the pin
            foreach ($this->pins as $pin) {
                // only check pins we haven't tried
                if (!isset($this->triedPins[$pin['keyId']])) {

                    // get last X characters of key identifier to compare
                    $keyId = mb_substr(
                        $pin['keyId'],
                        -$keyIdLength,
                        mb_strlen($pin['keyId'], '8bit'),
                        '8bit'
                    );

                    if ($keyId === $this->currentPin['keyId']) {
                        $foundPin = $pin['passphrase'];
                        $this->triedPins[$pin['keyId']] = $pin;
                        break;
                    }
                }
            }
        }

        return $this
            ->send($this->getData($foundPin))
            ->send($this->getOK());
    }

    /**
     * Sends information about this pinentry.
     *
     * @param string $data the information requested by the assuan server.
     *                     Currently only 'pid' is supported. Other requests
     *                     return no information.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function sendGetInfo($data)
    {
        $parts   = explode(' ', $data, 2);
        $command = reset($parts);

        switch ($command) {
        case 'pid':
            return $this->sendGetInfoPID();
        default:
            return $this->send($this->getOK());
        }

        return $this;
    }

    /**
     * Sends the PID of this pinentry to the assuan server.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function sendGetInfoPID()
    {
        return $this
            ->send($this->getData(getmypid()))
            ->send($this->getOK());
    }

    /**
     * Flags this pinentry for disconnection and sends an OK response.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function sendBye()
    {
        $return = $this->send($this->getOK('closing connection'));
        $this->moribund = true;

        return $return;
    }

    /**
     * Resets this pinentry and sends an OK response.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function sendReset()
    {
        $this->currentPin = null;
        $this->triedPins = array();

        return $this->send($this->getOK());
    }

    /**
     * Gets an OK response to send to the assuan server.
     *
     * @param string $data an optional message to include with the OK response.
     *
     * @return string the OK response.
     */
    protected function getOK($data = null)
    {
        $return = 'OK';

        if ($data) {
            $return .= ' '.$data;
        }

        return $return."\n";
    }

    /**
     * Gets data ready to send to the assuan server.
     *
     * Data is appropriately escaped and long lines are wrapped.
     *
     * @param string $data the data to send to the assuan server.
     *
     * @return string the properly escaped, formatted data.
     *
     * @see  http://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
     */
    protected function getData($data)
    {
        // Escape data. Only %, \n and \r need to be escaped but other
        // values are allowed to be escaped. See
        // http://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
        $data = rawurlencode($data);
        $data = $this->getWordWrappedData($data, 'D');

        return $data;
    }

    /**
     * Gets a comment ready to send to the assuan server.
     *
     * @param string $data the comment to send to the assuan server.
     *
     * @return string the properly formatted comment.
     *
     * @see  http://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
     */
    protected function getComment($data)
    {
        return $this->getWordWrappedData($data, '#');
    }

    /**
     * Wraps strings at 1,000 bytes without splitting UTF-8 multibyte
     * characters.
     *
     * Each line is prepended with the specified line prefix. Wrapped lines
     * are automatically appended with \ characters.
     *
     * Protocol strings are UTF-8 but maximum line length is 1,000 bytes.
     * <kbd>mb_strcut()</kbd> is used so we can limit line length by bytes
     * and not split characters across multiple lines.
     *
     * @param string $data   the data to wrap.
     * @param string $prefix a single character to use as the line prefix. For
     *                       example, 'D' or '#'.
     *
     * @return string the word-wrapped, prefixed string.
     *
     * @see http://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
     */
    protected function getWordWrappedData($data, $prefix)
    {
        $lines = array();

        do {
            if (mb_strlen($data, '8bit') > 997) {
                $line = $prefix.' '.mb_strcut($data, 0, 996, 'utf-8')."\\\n";
                $lines[] = $line;
                $lineLength = mb_strlen($line, '8bit') - 1;
                $dataLength = mb_substr($data, '8bit');
                $data = mb_substr(
                    $data,
                    $lineLength,
                    $dataLength - $lineLength,
                    '8bit'
                );
            } else {
                $lines[] = $prefix.' '.$data."\n";
                $data = '';
            }
        } while ($data != '');

        return implode('', $lines);
    }

    /**
     * Sends raw data to the assuan server.
     *
     * @param string $data the data to send.
     *
     * @return Crypt_GPG_PinEntry the current object, for fluent interface.
     */
    protected function send($data)
    {
        $this->log('-> '.$data, self::VERBOSITY_ALL);
        fwrite($this->stdout, $data);
        fflush($this->stdout);

        return $this;
    }
}
