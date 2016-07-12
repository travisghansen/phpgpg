<?php
namespace PhpGpg\Driver\GnuPG\Cli;

use PhpGpg\Driver\GnuPG\Cli;

class Engine
{
    /**
     * Size of data chunks that are sent to and retrieved from the IPC pipes.
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
     * Standard input file descriptor. This is used to pass data to the GPG
     * process.
     */
    const FD_INPUT = 0;

    /**
     * Standard output file descriptor. This is used to receive normal output
     * from the GPG process.
     */
    const FD_OUTPUT = 1;

    /**
     * Standard output file descriptor. This is used to receive error output
     * from the GPG process.
     */
    const FD_ERROR = 2;

    /**
     * GPG status output file descriptor. The status file descriptor outputs
     * detailed information for many GPG commands. See the second section of
     * the file <b>doc/DETAILS</b> in the
     * {@link http://www.gnupg.org/download/ GPG package} for a detailed
     * description of GPG's status output.
     */
    const FD_STATUS = 3;

    /**
     * Command input file descriptor. This is used for methods requiring
     * passphrases.
     */
    const FD_COMMAND = 4;

    /**
     * Extra message input file descriptor. This is used for passing signed
     * data when verifying a detached signature.
     */
    const FD_MESSAGE = 5;

    /**
     * Minimum version of GnuPG that is supported.
     */
    const MIN_VERSION = '1.0.2';

    /**
     * Whether or not to use debugging mode.
     *
     * When set to true, every GPG command is echoed before it is run. Sensitive
     * data is always handled using pipes and is not specified as part of the
     * command. As a result, sensitive data is never displayed when debug is
     * enabled. Sensitive data includes private key data and passphrases.
     *
     * Debugging is off by default.
     *
     * @var boolean
     */
    private $_debug = false;

    /**
     * Location of GPG binary.
     *
     * @var string
     */
    private $_binary = '';

    /**
     * Location of GnuPG agent binary.
     *
     * Only used for GnuPG 2.x
     *
     * @var string
     */
    private $_agent = '';

    /**
     * Directory containing the GPG key files.
     *
     * This property only contains the path when the <i>homedir</i> option
     * is specified in the constructor.
     *
     * @var string
     */
    private $_homedir = '';

    /**
     * Array of pipes used for communication with the GPG binary.
     *
     * This is an array of file descriptor resources.
     *
     * @var array
     */
    private $_pipes = array();

    /**
     * Array of pipes used for communication with the gpg-agent binary.
     *
     * This is an array of file descriptor resources.
     *
     * @var array
     */
    private $_agentPipes = array();

    /**
     * Array of currently opened pipes.
     *
     * This array is used to keep track of remaining opened pipes so they can
     * be closed when the GPG subprocess is finished. This array is a subset of
     * the $_pipes array and contains opened file
     * descriptor resources.
     *
     * @var array
     */
    private $_openPipes = array();

    /**
     * A handle for the GPG process.
     *
     * @var resource
     */
    private $_process = null;

    /**
     * A handle for the gpg-agent process.
     *
     * @var resource
     */
    private $_agentProcess = null;

    /**
     * GPG agent daemon socket and PID for running gpg-agent.
     *
     * @var string
     */
    private $_agentInfo = null;

    /**
     * Whether or not the operating system is Darwin (OS X).
     *
     * @var boolean
     */
    private $_isDarwin = false;

    /**
     * Commands to be sent to GPG's command input stream.
     *
     * @var string
     */
    private $_commandBuffer = '';

    /**
     * Array of status line handlers.
     *
     * @var array
     */
    private $_statusHandlers = array();

    /**
     * Array of error line handlers.
     *
     * @var array
     */
    private $_errorHandlers = array();

    /**
     * The error code of the current operation.
     *
     * @var integer
     */
    private $_errorCode = Cli::ERROR_NONE;

    /**
     * File related to the error code of the current operation.
     *
     * @var string
     */
    private $_errorFilename = '';

    /**
     * Key id related to the error code of the current operation.
     *
     * @var string
     */
    private $_errorkeyId = '';

    /**
     * The number of currently needed passphrases.
     *
     * If this is not zero when the GPG command is completed, the error code is
     * set to Cli::ERROR_MISSING_PASSPHRASE.
     */
    private $_needPassphrase = 0;

    /**
     * The input source.
     *
     * This is data to send to GPG. Either a string or a stream resource.
     *
     * @var string|resource
     */
    private $_input = null;

    /**
     * The extra message input source.
     *
     * Either a string or a stream resource.
     *
     * @var string|resource
     */
    private $_message = null;

    /**
     * The output location.
     *
     * This is where the output from GPG is sent. Either a string or a stream
     * resource.
     *
     * @var string|resource
     */
    private $_output = '';

    /**
     * The GPG operation to execute.
     *
     * @var string
     */
    private $_operation;

    /**
     * Arguments for the current operation.
     *
     * @var array
     */
    private $_arguments = array();

    /**
     * The version number of the GPG binary.
     *
     * @var string
     */
    private $_version = '';

    /**
     * Creates a new GPG engine.
     *
     * Available options are:
     *
     * - <kbd>string  homedir</kbd>        - the directory where the GPG
     *                                       keyring files are stored. If not
     *                                       specified, Crypt_GPG uses the
     *                                       default of <kbd>~/.gnupg</kbd>.
     * - <kbd>string  binary</kbd>         - the location of the GPG binary. If
     *                                       not specified, the driver attempts
     *                                       to auto-detect the GPG binary
     *                                       location using a list of known
     *                                       default locations for the current
     *                                       operating system. The option
     *                                       <kbd>gpgBinary</kbd> is a
     *                                       deprecated alias for this option.
     * - <kbd>string  agent</kbd>          - the location of the GnuPG agent
     *                                       binary. The gpg-agent is only
     *                                       used for GnuPG 2.x. If not
     *                                       specified, the engine attempts
     *                                       to auto-detect the gpg-agent
     *                                       binary location using a list of
     *                                       know default locations for the
     *                                       current operating system.
     * - <kbd>boolean debug</kbd>          - whether or not to use debug mode.
     *                                       When debug mode is on, all
     *                                       communication to and from the GPG
     *                                       subprocess is logged. This can be
     *                                       useful to diagnose errors when
     *                                       using Crypt_GPG.
     *
     * @param array $options optional. An array of options used to create the
     *                       GPG object. All options are optional and are
     *                       represented as key-value pairs.
     *
     * @throws Exception               if the <kbd>homedir</kbd> does not exist
     *                                 and cannot be created. This can happen if <kbd>homedir</kbd> is
     *                                 not specified, Crypt_GPG is run as the web user, and the web
     *                                 user has no home directory. This exception is also thrown if any
     *                                 of the options <kbd>publicKeyring</kbd>,
     *                                 <kbd>privateKeyring</kbd> or <kbd>trustDb</kbd> options are
     *                                 specified but the files do not exist or are are not readable.
     *                                 This can happen if the user running the Crypt_GPG process (for
     *                                 example, the Apache user) does not have permission to read the
     *                                 files.
     * @throws Exception               if the provided <kbd>binary</kbd> is invalid, or
     *                                 if no <kbd>binary</kbd> is provided and no suitable binary could
     *                                 be found.
     * @throws Exception               if the provided <kbd>agent</kbd> is invalid, or
     *                                 if no <kbd>agent</kbd> is provided and no suitable gpg-agent
     *                                 cound be found.
     */
    public function __construct(array $options = array())
    {
        $this->_isDarwin = (strncmp(strtoupper(PHP_OS), 'DARWIN', 6) === 0);

        // get homedir
        if (array_key_exists('homedir', $options)) {
            $this->_homedir = (string) $options['homedir'];
        } else {
            if (extension_loaded('posix')) {
                // note: this requires the package OS dep exclude 'windows'
                $info = posix_getpwuid(posix_getuid());
                $this->_homedir = $info['dir'].'/.gnupg';
            } else {
                if (isset($_SERVER['HOME'])) {
                    $this->_homedir = $_SERVER['HOME'];
                } else {
                    $this->_homedir = getenv('HOME');
                }
            }

            if ($this->_homedir === false) {
                throw new \Exception(
                    'Could not locate homedir. Please specify the homedir '.
                    'to use with the \'homedir\' option when instantiating '.
                    'the Crypt_GPG object.'
                );
            }
        }

        // attempt to create homedir if it does not exist
        if (!is_dir($this->_homedir)) {
            if (@mkdir($this->_homedir, 0777, true)) {
                // Set permissions on homedir. Parent directories are created
                // with 0777, homedir is set to 0700.
                chmod($this->_homedir, 0700);
            } else {
                throw new \Exception(
                    'The \'homedir\' "'.$this->_homedir.'" is not '.
                    'readable or does not exist and cannot be created. This '.
                    'can happen if \'homedir\' is not specified in the '.
                    'Crypt_GPG options, Crypt_GPG is run as the web user, '.
                    'and the web user has no home directory.',
                    0
                );
            }
        }

        // check homedir permissions (See Bug #19833)
        if (!is_executable($this->_homedir)) {
            throw new \Exception(
                'The \'homedir\' "'.$this->_homedir.'" is not enterable '.
                'by the current user. Please check the permissions on your '.
                'homedir and make sure the current user can both enter and '.
                'write to the directory.',
                0
            );
        }
        if (!is_writeable($this->_homedir)) {
            throw new \Exception(
                'The \'homedir\' "'.$this->_homedir.'" is not writable '.
                'by the current user. Please check the permissions on your '.
                'homedir and make sure the current user can both enter and '.
                'write to the directory.',
                0
            );
        }

        // get binary
        if (array_key_exists('binary', $options)) {
            $this->_binary = (string) $options['binary'];
        } elseif (array_key_exists('gpgBinary', $options)) {
            // deprecated alias
            $this->_binary = (string) $options['gpgBinary'];
        } else {
            $this->_binary = $this->_getBinary();
        }

        if ($this->_binary == '' || !is_executable($this->_binary)) {
            throw new \Exception(
                'GPG binary not found. If you are sure the GPG binary is '.
                'installed, please specify the location of the GPG binary '.
                'using the \'binary\' driver option.'
            );
        }

        // get agent
        if (array_key_exists('agent', $options)) {
            $this->_agent = (string) $options['agent'];
        } else {
            $this->_agent = $this->_getAgent();
        }

        if ($this->_agent == '' || !is_executable($this->_agent)) {
            throw new \Exception(
                'gpg-agent binary not found. If you are sure the gpg-agent '.
                'is installed, please specify the location of the gpg-agent '.
                'binary using the \'agent\' driver option.'
            );
        }

        if (array_key_exists('debug', $options)) {
            $this->_debug = (boolean) $options['debug'];
        }
    }

    /**
     * Closes open GPG subprocesses when this object is destroyed.
     *
     * Subprocesses should never be left open by this class unless there is
     * an unknown error and unexpected script termination occurs.
     */
    public function __destruct()
    {
        $this->_closeSubprocess();
    }

    /**
     * Adds an error handler method.
     *
     * The method is run every time a new error line is received from the GPG
     * subprocess. The handler method must accept the error line to be handled
     * as its first parameter.
     *
     * @param callback $callback the callback method to use.
     * @param array    $args     optional. Additional arguments to pass as
     *                           parameters to the callback method.
     */
    public function addErrorHandler($callback, array $args = array())
    {
        $this->_errorHandlers[] = array(
            'callback' => $callback,
            'args'     => $args,
        );
    }

    /**
     * Adds a status handler method.
     *
     * The method is run every time a new status line is received from the
     * GPG subprocess. The handler method must accept the status line to be
     * handled as its first parameter.
     *
     * @param callback $callback the callback method to use.
     * @param array    $args     optional. Additional arguments to pass as
     *                           parameters to the callback method.
     */
    public function addStatusHandler($callback, array $args = array())
    {
        $this->_statusHandlers[] = array(
            'callback' => $callback,
            'args'     => $args,
        );
    }

    /**
     * Sends a command to the GPG subprocess over the command file-descriptor
     * pipe.
     *
     * @param string $command the command to send.
     *
     *
     * @sensitive $command
     */
    public function sendCommand($command)
    {
        if (array_key_exists(self::FD_COMMAND, $this->_openPipes)) {
            $this->_commandBuffer .= $command.PHP_EOL;
        }
    }

    /**
     * Resets the GPG engine, preparing it for a new operation.
     */
    public function reset()
    {
        $this->_operation      = '';
        $this->_arguments      = array();
        $this->_input          = null;
        $this->_message        = null;
        $this->_output         = '';
        $this->_errorCode      = Cli::ERROR_NONE;
        $this->_needPassphrase = 0;
        $this->_commandBuffer  = '';

        $this->_statusHandlers = array();
        $this->_errorHandlers  = array();

        $this->addStatusHandler(array($this, '_handleErrorStatus'));
        $this->addErrorHandler(array($this, '_handleErrorError'));

        if ($this->_debug) {
            $this->addStatusHandler(array($this, '_handleDebugStatus'));
            $this->addErrorHandler(array($this, '_handleDebugError'));
        }
    }

    /**
     * Runs the current GPG operation.
     *
     * This creates and manages the GPG subprocess.
     *
     * The operation must be set with Engine::setOperation()}
     * before this method is called.
     *
     *
     * @throws Exception if no operation is specified.
     */
    public function run()
    {
        if ($this->_operation === '') {
            throw new \Exception('No GPG operation '.
                'specified. Use Engine::setOperation() before '.
                'calling Engine::run().');
        }

        $this->_openSubprocess();
        $this->_process();
        $this->_closeSubprocess();
    }

    /**
     * Gets the error code of the last executed operation.
     *
     * This value is only meaningful after Engine::run() has
     * been executed.
     *
     * @return integer the error code of the last executed operation.
     */
    public function getErrorCode()
    {
        return $this->_errorCode;
    }

    /**
     * Gets the file related to the error code of the last executed operation.
     *
     * This value is only meaningful after Engine::run() has
     * been executed. If there is no file related to the error, an empty string
     * is returned.
     *
     * @return string the file related to the error code of the last executed
     *                operation.
     */
    public function getErrorFilename()
    {
        return $this->_errorFilename;
    }

    /**
     * Gets the key id related to the error code of the last executed operation.
     *
     * This value is only meaningful after Engine::run() has
     * been executed. If there is no key id related to the error, an empty
     * string is returned.
     *
     * @return string the key id related to the error code of the last executed
     *                operation.
     */
    public function getErrorKeyId()
    {
        return $this->_errorKeyId;
    }

    /**
     * Sets the input source for the current GPG operation.
     *
     * @param string|resource &$input either a reference to the string
     *                                containing the input data or an open
     *                                stream resource containing the input
     *                                data.
     */
    public function setInput(&$input)
    {
        $this->_input = & $input;
    }

    /**
     * Sets the message source for the current GPG operation.
     *
     * Detached signature data should be specified here.
     *
     * @param string|resource &$message either a reference to the string
     *                                  containing the message data or an open
     *                                  stream resource containing the message
     *                                  data.
     */
    public function setMessage(&$message)
    {
        $this->_message = & $message;
    }

    /**
     * Sets the output destination for the current GPG operation.
     *
     * @param string|resource &$output either a reference to the string in
     *                                 which to store GPG output or an open
     *                                 stream resource to which the output data
     *                                 should be written.
     */
    public function setOutput(&$output)
    {
        $this->_output = & $output;
    }

    /**
     * Sets the operation to perform.
     *
     * @param string $operation the operation to perform. This should be one
     *                          of GPG's operations. For example,
     *                          <kbd>--encrypt</kbd>, <kbd>--decrypt</kbd>,
     *                          <kbd>--sign</kbd>, etc.
     * @param array  $arguments optional. Additional arguments for the GPG
     *                          subprocess. See the GPG manual for specific
     *                          values.
     */
    public function setOperation($operation, array $arguments = array())
    {
        $this->_operation = $operation;
        $this->_arguments = $arguments;
    }

    /**
     * Gets the version of the GnuPG binary.
     *
     * @return string a version number string containing the version of GnuPG
     *                being used. This value is suitable to use with PHP's
     *                version_compare() function.
     *
     * @throws Exception                      if an unknown or unexpected error occurs.
     *                                        Use the <kbd>debug</kbd> option and file a bug report if these
     *                                        exceptions occur.
     * @throws Exception                      if the provided binary is not
     *                                        GnuPG or if the GnuPG version is less than 1.0.2.
     */
    public function getVersion()
    {
        if ($this->_version == '') {
            $options = array(
                'homedir' => $this->_homedir,
                'binary'  => $this->_binary,
                'debug'   => $this->_debug,
            );

            $engine = new self($options);
            $info   = '';

            // Set a garbage version so we do not end up looking up the version
            // recursively.
            $engine->_version = '1.0.0';

            $engine->reset();
            $engine->setOutput($info);
            $engine->setOperation('--version --no-permission-warning');
            $engine->run();

            $code = $this->getErrorCode();

            if ($code !== Cli::ERROR_NONE) {
                throw new \Exception(
                    'Unknown error getting GnuPG version information.',
                    $code
                );
            }

            $matches    = array();
            $expression = '#gpg \(GnuPG[A-Za-z0-9/]*?\) (\S+)#';

            if (preg_match($expression, $info, $matches) === 1) {
                $this->_version = $matches[1];
            } else {
                throw new \Exception(
                    'No GnuPG version information provided by the binary "'.
                    $this->_binary.'". Are you sure it is GnuPG?');
            }

            if (version_compare($this->_version, self::MIN_VERSION, 'lt')) {
                throw new \Exception(
                    'The version of GnuPG being used ('.$this->_version.
                    ') is not supported by Crypt_GPG. The minimum version '.
                    'required by Crypt_GPG is '.self::MIN_VERSION);
            }
        }

        return $this->_version;
    }

    /**
     * Handles error values in the status output from GPG.
     *
     * This method is responsible for setting the
     * Engine::$_errorCode. See <b>doc/DETAILS</b> in the
     * http://www.gnupg.org/download/ GPG distribution for detailed
     * information on GPG's status output.
     *
     * @param string $line the status line to handle.
     */
    private function _handleErrorStatus($line)
    {
        $tokens = explode(' ', $line);
        switch ($tokens[0]) {
        case 'BAD_PASSPHRASE':
            $this->_errorCode = Cli::ERROR_BAD_PASSPHRASE;
            break;

        case 'MISSING_PASSPHRASE':
            $this->_errorCode = Cli::ERROR_MISSING_PASSPHRASE;
            break;

        case 'NODATA':
            $this->_errorCode = Cli::ERROR_NO_DATA;
            break;

        case 'DELETE_PROBLEM':
            if ($tokens[1] == '1') {
                $this->_errorCode = Cli::ERROR_KEY_NOT_FOUND;
                break;
            } elseif ($tokens[1] == '2') {
                $this->_errorCode = Cli::ERROR_DELETE_PRIVATE_KEY;
                break;
            }
            break;

        case 'IMPORT_RES':
            if ($tokens[12] > 0) {
                $this->_errorCode = Cli::ERROR_DUPLICATE_KEY;
            }
            break;

        case 'NO_PUBKEY':
        case 'NO_SECKEY':
            $this->_errorKeyId = $tokens[1];
            $this->_errorCode  = Cli::ERROR_KEY_NOT_FOUND;
            break;

        case 'NEED_PASSPHRASE':
            $this->_needPassphrase++;
            break;

        case 'GOOD_PASSPHRASE':
            $this->_needPassphrase--;
            break;

        case 'EXPSIG':
        case 'EXPKEYSIG':
        case 'REVKEYSIG':
        case 'BADSIG':
            $this->_errorCode = Cli::ERROR_BAD_SIGNATURE;
            break;

        }
    }

    /**
     * Handles error values in the error output from GPG.
     *
     * This method is responsible for setting the
     * Engine::$_errorCode.
     *
     * @param string $line the error line to handle.
     */
    private function _handleErrorError($line)
    {
        if ($this->_errorCode === Cli::ERROR_NONE) {
            $pattern = '/no valid OpenPGP data found/';
            if (preg_match($pattern, $line) === 1) {
                $this->_errorCode = Cli::ERROR_NO_DATA;
            }
        }

        if ($this->_errorCode === Cli::ERROR_NONE) {
            $pattern = '/No secret key|secret key not available/';
            if (preg_match($pattern, $line) === 1) {
                $this->_errorCode = Cli::ERROR_KEY_NOT_FOUND;
            }
        }

        if ($this->_errorCode === Cli::ERROR_NONE) {
            $pattern = '/No public key|public key not found/';
            if (preg_match($pattern, $line) === 1) {
                $this->_errorCode = Cli::ERROR_KEY_NOT_FOUND;
            }
        }

        if ($this->_errorCode === Cli::ERROR_NONE) {
            $matches = array();
            $pattern = '/can\'t (?:access|open) `(.*?)\'/';
            if (preg_match($pattern, $line, $matches) === 1) {
                $this->_errorFilename = $matches[1];
                $this->_errorCode = Cli::ERROR_FILE_PERMISSIONS;
            }
        }
    }

    /**
     * Displays debug output for status lines.
     *
     * @param string $line the status line to handle.
     */
    private function _handleDebugStatus($line)
    {
        $this->_debug('STATUS: '.$line);
    }

    /**
     * Displays debug output for error lines.
     *
     * @param string $line the error line to handle.
     */
    private function _handleDebugError($line)
    {
        $this->_debug('ERROR: '.$line);
    }

    /**
     * Performs internal streaming operations for the subprocess using either
     * strings or streams as input / output points.
     *
     * This is the main I/O loop for streaming to and from the GPG subprocess.
     *
     * The implementation of this method is verbose mainly for performance
     * reasons. Adding streams to a lookup array and looping the array inside
     * the main I/O loop would be siginficantly slower for large streams.
     *
     *
     * @throws Exception           if there is an error selecting streams for
     *                             reading or writing. If this occurs, please file a bug report at
     *                             http://pear.php.net/bugs/report.php?package=Crypt_GPG.
     */
    private function _process()
    {
        $this->_debug('BEGIN PROCESSING');

        $this->_commandBuffer = '';    // buffers input to GPG
        $messageBuffer        = '';    // buffers input to GPG
        $inputBuffer          = '';    // buffers input to GPG
        $outputBuffer         = '';    // buffers output from GPG
        $statusBuffer         = '';    // buffers output from GPG
        $errorBuffer          = '';    // buffers output from GPG
        $inputComplete        = false; // input stream is completely buffered
        $messageComplete      = false; // message stream is completely buffered

        if (is_string($this->_input)) {
            $inputBuffer   = $this->_input;
            $inputComplete = true;
        }

        if (is_string($this->_message)) {
            $messageBuffer   = $this->_message;
            $messageComplete = true;
        }

        if (is_string($this->_output)) {
            $outputBuffer = & $this->_output;
        }

        // convenience variables
        $fdInput   = $this->_pipes[self::FD_INPUT];
        $fdOutput  = $this->_pipes[self::FD_OUTPUT];
        $fdError   = $this->_pipes[self::FD_ERROR];
        $fdStatus  = $this->_pipes[self::FD_STATUS];
        $fdCommand = $this->_pipes[self::FD_COMMAND];
        $fdMessage = $this->_pipes[self::FD_MESSAGE];

        // select loop delay in milliseconds
        $delay = 0;

        while (true) {
            $inputStreams     = array();
            $outputStreams    = array();
            $exceptionStreams = array();

            // set up input streams
            if (is_resource($this->_input) && !$inputComplete) {
                if (feof($this->_input)) {
                    $inputComplete = true;
                } else {
                    $inputStreams[] = $this->_input;
                }
            }

            // close GPG input pipe if there is no more data
            if ($inputBuffer == '' && $inputComplete) {
                $this->_debug('=> closing GPG input pipe');
                $this->_closePipe(self::FD_INPUT);
            }

            if (is_resource($this->_message) && !$messageComplete) {
                if (feof($this->_message)) {
                    $messageComplete = true;
                } else {
                    $inputStreams[] = $this->_message;
                }
            }

            // close GPG message pipe if there is no more data
            if ($messageBuffer == '' && $messageComplete) {
                $this->_debug('=> closing GPG message pipe');
                $this->_closePipe(self::FD_MESSAGE);
            }

            if (!feof($fdOutput)) {
                $inputStreams[] = $fdOutput;
            }

            if (!feof($fdStatus)) {
                $inputStreams[] = $fdStatus;
            }

            if (!feof($fdError)) {
                $inputStreams[] = $fdError;
            }

            // set up output streams
            if ($outputBuffer != '' && is_resource($this->_output)) {
                $outputStreams[] = $this->_output;
            }

            if ($this->_commandBuffer != '' && is_resource($fdCommand)) {
                $outputStreams[] = $fdCommand;
            }

            if ($messageBuffer != '' && is_resource($fdMessage)) {
                $outputStreams[] = $fdMessage;
            }

            if ($inputBuffer != '' && is_resource($fdInput)) {
                $outputStreams[] = $fdInput;
            }

            // no streams left to read or write, we're all done
            if (count($inputStreams) === 0 && count($outputStreams) === 0) {
                break;
            }

            $this->_debug('selecting streams');

            $ready = stream_select(
                $inputStreams,
                $outputStreams,
                $exceptionStreams,
                null
            );

            $this->_debug('=> got '.$ready);

            if ($ready === false) {
                throw new \Exception(
                    'Error selecting stream for communication with GPG '.
                    'subprocess.'
                );
            }

            if ($ready === 0) {
                throw new \Exception(
                    'stream_select() returned 0. This can not happen!'
                );
            }

            // write input (to GPG)
            if (in_array($fdInput, $outputStreams, true)) {
                $this->_debug('GPG is ready for input');

                $chunk = ByteUtils::substr(
                    $inputBuffer,
                    0,
                    self::CHUNK_SIZE
                );

                $length = ByteUtils::strlen($chunk);

                $this->_debug(
                    '=> about to write '.$length.' bytes to GPG input'
                );

                $length = fwrite($fdInput, $chunk, $length);
                if ($length === 0) {
                    // If we wrote 0 bytes it was either EAGAIN or EPIPE. Since
                    // the pipe was seleted for writing, we assume it was EPIPE.
                    // There's no way to get the actual erorr code in PHP. See
                    // PHP Bug #39598. https://bugs.php.net/bug.php?id=39598
                    $this->_debug('=> broken pipe on GPG input');
                    $this->_debug('=> closing pipe GPG input');
                    $this->_closePipe(self::FD_INPUT);
                } else {
                    $this->_debug('=> wrote '.$length.' bytes');
                    $inputBuffer = ByteUtils::substr(
                        $inputBuffer,
                        $length
                    );
                }
            }

            // read input (from PHP stream)
            if (in_array($this->_input, $inputStreams, true)) {
                $this->_debug('input stream is ready for reading');
                $this->_debug(
                    '=> about to read '.self::CHUNK_SIZE.
                    ' bytes from input stream'
                );

                $chunk        = fread($this->_input, self::CHUNK_SIZE);
                $length       = ByteUtils::strlen($chunk);
                $inputBuffer .= $chunk;

                $this->_debug('=> read '.$length.' bytes');
            }

            // write message (to GPG)
            if (in_array($fdMessage, $outputStreams, true)) {
                $this->_debug('GPG is ready for message data');

                $chunk = ByteUtils::substr(
                    $messageBuffer,
                    0,
                    self::CHUNK_SIZE
                );

                $length = ByteUtils::strlen($chunk);

                $this->_debug(
                    '=> about to write '.$length.' bytes to GPG message'
                );

                $length = fwrite($fdMessage, $chunk, $length);
                if ($length === 0) {
                    // If we wrote 0 bytes it was either EAGAIN or EPIPE. Since
                    // the pipe was seleted for writing, we assume it was EPIPE.
                    // There's no way to get the actual erorr code in PHP. See
                    // PHP Bug #39598. https://bugs.php.net/bug.php?id=39598
                    $this->_debug('=> broken pipe on GPG message');
                    $this->_debug('=> closing pipe GPG message');
                    $this->_closePipe(self::FD_MESSAGE);
                } else {
                    $this->_debug('=> wrote '.$length.' bytes');
                    $messageBuffer = ByteUtils::substr(
                        $messageBuffer,
                        $length
                    );
                }
            }

            // read message (from PHP stream)
            if (in_array($this->_message, $inputStreams, true)) {
                $this->_debug('message stream is ready for reading');
                $this->_debug(
                    '=> about to read '.self::CHUNK_SIZE.
                    ' bytes from message stream'
                );

                $chunk          = fread($this->_message, self::CHUNK_SIZE);
                $length         = ByteUtils::strlen($chunk);
                $messageBuffer .= $chunk;

                $this->_debug('=> read '.$length.' bytes');
            }

            // read output (from GPG)
            if (in_array($fdOutput, $inputStreams, true)) {
                $this->_debug('GPG output stream ready for reading');
                $this->_debug(
                    '=> about to read '.self::CHUNK_SIZE.
                    ' bytes from GPG output'
                );

                $chunk         = fread($fdOutput, self::CHUNK_SIZE);
                $length        = ByteUtils::strlen($chunk);
                $outputBuffer .= $chunk;

                $this->_debug('=> read '.$length.' bytes');
            }

            // write output (to PHP stream)
            if (in_array($this->_output, $outputStreams, true)) {
                $this->_debug('output stream is ready for data');

                $chunk = ByteUtils::substr(
                    $outputBuffer,
                    0,
                    self::CHUNK_SIZE
                );

                $length = ByteUtils::strlen($chunk);

                $this->_debug(
                    '=> about to write '.$length.' bytes to output stream'
                );

                $length = fwrite($this->_output, $chunk, $length);

                $this->_debug('=> wrote '.$length.' bytes');

                $outputBuffer = ByteUtils::substr(
                    $outputBuffer,
                    $length
                );
            }

            // read error (from GPG)
            if (in_array($fdError, $inputStreams, true)) {
                $this->_debug('GPG error stream ready for reading');
                $this->_debug(
                    '=> about to read '.self::CHUNK_SIZE.
                    ' bytes from GPG error'
                );

                $chunk        = fread($fdError, self::CHUNK_SIZE);
                $length       = ByteUtils::strlen($chunk);
                $errorBuffer .= $chunk;

                $this->_debug('=> read '.$length.' bytes');

                // pass lines to error handlers
                while (($pos = strpos($errorBuffer, PHP_EOL)) !== false) {
                    $line = ByteUtils::substr($errorBuffer, 0, $pos);
                    foreach ($this->_errorHandlers as $handler) {
                        array_unshift($handler['args'], $line);
                        call_user_func_array(
                            $handler['callback'],
                            $handler['args']
                        );

                        array_shift($handler['args']);
                    }
                    $errorBuffer = ByteUtils::substr(
                        $errorBuffer,
                        $pos + ByteUtils::strlen(PHP_EOL)
                    );
                }
            }

            // read status (from GPG)
            if (in_array($fdStatus, $inputStreams, true)) {
                $this->_debug('GPG status stream ready for reading');
                $this->_debug(
                    '=> about to read '.self::CHUNK_SIZE.
                    ' bytes from GPG status'
                );

                $chunk         = fread($fdStatus, self::CHUNK_SIZE);
                $length        = ByteUtils::strlen($chunk);
                $statusBuffer .= $chunk;

                $this->_debug('=> read '.$length.' bytes');

                // pass lines to status handlers
                while (($pos = strpos($statusBuffer, PHP_EOL)) !== false) {
                    $line = ByteUtils::substr($statusBuffer, 0, $pos);
                    // only pass lines beginning with magic prefix
                    if (ByteUtils::substr($line, 0, 9) == '[GNUPG:] ') {
                        $line = ByteUtils::substr($line, 9);
                        foreach ($this->_statusHandlers as $handler) {
                            array_unshift($handler['args'], $line);
                            call_user_func_array(
                                $handler['callback'],
                                $handler['args']
                            );

                            array_shift($handler['args']);
                        }
                    }
                    $statusBuffer = ByteUtils::substr(
                        $statusBuffer,
                        $pos + ByteUtils::strlen(PHP_EOL)
                    );
                }
            }

            // write command (to GPG)
            if (in_array($fdCommand, $outputStreams, true)) {
                $this->_debug('GPG is ready for command data');

                // send commands
                $chunk = ByteUtils::substr(
                    $this->_commandBuffer,
                    0,
                    self::CHUNK_SIZE
                );

                $length = ByteUtils::strlen($chunk);

                $this->_debug(
                    '=> about to write '.$length.' bytes to GPG command'
                );

                $length = fwrite($fdCommand, $chunk, $length);
                if ($length === 0) {
                    // If we wrote 0 bytes it was either EAGAIN or EPIPE. Since
                    // the pipe was seleted for writing, we assume it was EPIPE.
                    // There's no way to get the actual erorr code in PHP. See
                    // PHP Bug #39598. https://bugs.php.net/bug.php?id=39598
                    $this->_debug('=> broken pipe on GPG command');
                    $this->_debug('=> closing pipe GPG command');
                    $this->_closePipe(self::FD_COMMAND);
                } else {
                    $this->_debug('=> wrote '.$length);
                    $this->_commandBuffer = ByteUtils::substr(
                        $this->_commandBuffer,
                        $length
                    );
                }
            }

            if (count($outputStreams) === 0 || count($inputStreams) === 0) {
                // we have an I/O imbalance, increase the select loop delay
                // to smooth things out
                $delay += 10;
            } else {
                // things are running smoothly, decrease the delay
                $delay -= 8;
                $delay = max(0, $delay);
            }

            if ($delay > 0) {
                usleep($delay);
            }
        } // end loop while streams are open

        $this->_debug('END PROCESSING');
    }

    /**
     * Opens an internal GPG subprocess for the current operation.
     *
     * Opens a GPG subprocess, then connects the subprocess to some pipes. Sets
     * the private class property Engine::$_process to
     * the new subprocess.
     *
     *
     * @throws Exception if the subprocess could not be
     *                                           opened.
     */
    private function _openSubprocess()
    {
        $version = $this->getVersion();

        // Binary operations will not work on Windows with PHP < 5.2.6. This is
        // in case stream_select() ever works on Windows.
        $rb = (version_compare(PHP_VERSION, '5.2.6') < 0) ? 'r' : 'rb';
        $wb = (version_compare(PHP_VERSION, '5.2.6') < 0) ? 'w' : 'wb';

        $env = $_ENV;

        // Newer versions of GnuPG return localized results. Crypt_GPG only
        // works with English, so set the locale to 'C' for the subprocess.
        $env['LC_ALL'] = 'C';

        // If using GnuPG 2.x start the gpg-agent
        if (version_compare($version, '2.0.0', 'ge')) {
            $agentCommandLine = $this->_agent;

            $agentArguments = array(
                '--options /dev/null', // ignore any saved options
                '--csh', // output is easier to parse
                '--keep-display', // prevent passing --display to pinentry
                '--no-grab',
                '--ignore-cache-for-signing',
                '--pinentry-touch-file /dev/null',
                '--disable-scdaemon',
                '--no-use-standard-socket',
                '--pinentry-program '.escapeshellarg($this->_getPinEntry()),
            );

            if ($this->_homedir) {
                $agentArguments[] = '--homedir '.
                    escapeshellarg($this->_homedir);
            }

            $agentCommandLine .= ' '.implode(' ', $agentArguments)
                .' --daemon';

            $agentDescriptorSpec = array(
                self::FD_INPUT   => array('pipe', $rb), // stdin
                self::FD_OUTPUT  => array('pipe', $wb), // stdout
                self::FD_ERROR   => array('pipe', $wb),  // stderr
            );

            $this->_debug('OPENING GPG-AGENT SUBPROCESS WITH THE FOLLOWING COMMAND:');
            $this->_debug($agentCommandLine);

            $this->_agentProcess = proc_open(
                $agentCommandLine,
                $agentDescriptorSpec,
                $this->_agentPipes,
                null,
                $env,
                array('binary_pipes' => true)
            );

            if (!is_resource($this->_agentProcess)) {
                throw new \Exception(
                    'Unable to open gpg-agent subprocess. ('.$agentCommandLine.')'
                );
            }

            // Get GPG_AGENT_INFO and set environment variable for gpg process.
            // This is a blocking read, but is only 1 line.
            $agentInfo = fread(
                $this->_agentPipes[self::FD_OUTPUT],
                self::CHUNK_SIZE
            );

            $agentInfo             = explode(' ', $agentInfo, 3);
            $this->_agentInfo      = $agentInfo[2];
            $env['GPG_AGENT_INFO'] = $this->_agentInfo;

            // gpg-agent daemon is started, we can close the launching process
            $this->_closeAgentLaunchProcess();
        }

        $commandLine = $this->_binary;

        $defaultArguments = array(
            '--status-fd '.escapeshellarg(self::FD_STATUS),
            '--command-fd '.escapeshellarg(self::FD_COMMAND),
            '--no-secmem-warning',
            '--no-tty',
            '--no-default-keyring', // ignored if keying files are not specified
            '--no-options',          // prevent creation of ~/.gnupg directory
        );

        if (version_compare($version, '1.0.7', 'ge')) {
            if (version_compare($version, '2.0.0', 'lt')) {
                $defaultArguments[] = '--no-use-agent';
            }
            $defaultArguments[] = '--no-permission-warning';
        }

        if (version_compare($version, '1.4.2', 'ge')) {
            $defaultArguments[] = '--exit-on-status-write-error';
        }

        if (version_compare($version, '1.3.2', 'ge')) {
            $defaultArguments[] = '--trust-model always';
        } else {
            $defaultArguments[] = '--always-trust';
        }

        $arguments = array_merge($defaultArguments, $this->_arguments);

        if ($this->_homedir) {
            $arguments[] = '--homedir '.escapeshellarg($this->_homedir);

            // the random seed file makes subsequent actions faster so only
            // disable it if we have to.
            if (!is_writeable($this->_homedir)) {
                $arguments[] = '--no-random-seed-file';
            }
        }

        $commandLine .= ' '.implode(' ', $arguments).' '.
            $this->_operation;

        $descriptorSpec = array(
            self::FD_INPUT   => array('pipe', $rb), // stdin
            self::FD_OUTPUT  => array('pipe', $wb), // stdout
            self::FD_ERROR   => array('pipe', $wb), // stderr
            self::FD_STATUS  => array('pipe', $wb), // status
            self::FD_COMMAND => array('pipe', $rb), // command
            self::FD_MESSAGE => array('pipe', $rb),  // message
        );

        $this->_debug('OPENING GPG SUBPROCESS WITH THE FOLLOWING COMMAND:');
        $this->_debug($commandLine);

        $this->_process = proc_open(
            $commandLine,
            $descriptorSpec,
            $this->_pipes,
            null,
            $env,
            array('binary_pipes' => true)
        );

        if (!is_resource($this->_process)) {
            throw new \Exception(
                'Unable to open GPG subprocess. ('.$commandLine.')');
        }

        // Set streams as non-blocking. See Bug #18618.
        foreach ($this->_pipes as $pipe) {
            stream_set_blocking($pipe, 0);
        }

        $this->_openPipes = $this->_pipes;
        $this->_errorCode = Cli::ERROR_NONE;
    }

    /**
     * Closes a the internal GPG subprocess.
     *
     * Closes the internal GPG subprocess. Sets the private class property
     * {@link Crypt_GPG_Engine::$_process} to null.
     *
     *
     * @see Crypt_GPG_Engine::_openSubprocess()
     * @see Crypt_GPG_Engine::$_process
     */
    private function _closeSubprocess()
    {
        // clear PINs from environment if they were set
        $_ENV['PINENTRY_USER_DATA'] = null;

        if (is_resource($this->_process)) {
            $this->_debug('CLOSING GPG SUBPROCESS');

            // close remaining open pipes
            foreach (array_keys($this->_openPipes) as $pipeNumber) {
                $this->_closePipe($pipeNumber);
            }

            $exitCode = proc_close($this->_process);

            if ($exitCode != 0) {
                $this->_debug(
                    '=> subprocess returned an unexpected exit code: '.
                    $exitCode
                );

                if ($this->_errorCode === Cli::ERROR_NONE) {
                    if ($this->_needPassphrase > 0) {
                        $this->_errorCode = Cli::ERROR_MISSING_PASSPHRASE;
                    } else {
                        $this->_errorCode = Cli::ERROR_UNKNOWN;
                    }
                }
            }

            $this->_process = null;
            $this->_pipes   = array();
        }

        $this->_closeAgentLaunchProcess();

        if ($this->_agentInfo !== null) {
            $this->_debug('STOPPING GPG-AGENT DAEMON');

            $parts   = explode(':', $this->_agentInfo, 3);
            $pid     = $parts[1];
            $process = new ProcessControl($pid);

            // terminate agent daemon
            $process->terminate();

            while ($process->isRunning()) {
                usleep(10000); // 10 ms
                $process->terminate();
            }

            $this->_agentInfo = null;

            $this->_debug('GPG-AGENT DAEMON STOPPED');
        }
    }

    private function _closeAgentLaunchProcess()
    {
        if (is_resource($this->_agentProcess)) {
            $this->_debug('CLOSING GPG-AGENT LAUNCH PROCESS');

            // close agent pipes
            foreach ($this->_agentPipes as $pipe) {
                fflush($pipe);
                fclose($pipe);
            }

            // close agent launching process
            proc_close($this->_agentProcess);

            $this->_agentProcess = null;
            $this->_agentPipes   = array();

            $this->_debug('GPG-AGENT LAUNCH PROCESS CLOSED');
        }
    }

    /**
     * Closes an opened pipe used to communicate with the GPG subprocess.
     *
     * If the pipe is already closed, it is ignored. If the pipe is open, it
     * is flushed and then closed.
     *
     * @param integer $pipeNumber the file descriptor number of the pipe to
     *                            close.
     */
    private function _closePipe($pipeNumber)
    {
        $pipeNumber = intval($pipeNumber);
        if (array_key_exists($pipeNumber, $this->_openPipes)) {
            fflush($this->_openPipes[$pipeNumber]);
            fclose($this->_openPipes[$pipeNumber]);
            unset($this->_openPipes[$pipeNumber]);
        }
    }

    /**
     * Gets the name of the GPG binary for the current operating system.
     *
     * This method is called if the '<kbd>binary</kbd>' option is <i>not</i>
     * specified when creating this driver.
     *
     * @return string the name of the GPG binary for the current operating
     *                system. If no suitable binary could be found, an empty
     *                string is returned.
     */
    private function _getBinary()
    {
        $binary = '';

        if ($this->_isDarwin) {
            $binaryFiles = array(
                '/opt/local/bin/gpg', // MacPorts
                '/usr/local/bin/gpg', // Mac GPG
                '/sw/bin/gpg',        // Fink
                '/usr/bin/gpg',
            );
        } else {
            $binaryFiles = array(
                '/usr/local/bin/gpg',
                '/usr/bin/gpg',
            );
        }

        foreach ($binaryFiles as $binaryFile) {
            if (is_executable($binaryFile)) {
                $binary = $binaryFile;
                break;
            }
        }

        return $binary;
    }

    private function _getAgent()
    {
        $agent = '';

        if ($this->_isDarwin) {
            $agentFiles = array(
                '/opt/local/bin/gpg-agent', // MacPorts
                '/usr/local/bin/gpg-agent', // Mac GPG
                '/sw/bin/gpg-agent',        // Fink
                '/usr/bin/gpg-agent',
            );
        } else {
            $agentFiles = array(
                '/usr/local/bin/gpg-agent',
                '/usr/bin/gpg-agent',
            );
        }

        foreach ($agentFiles as $agentFile) {
            if (is_executable($agentFile)) {
                $agent = $agentFile;
                break;
            }
        }

        return $agent;
    }

    private function _getPinEntry()
    {
        $pinEntry = dirname(__FILE__).DIRECTORY_SEPARATOR.'pinentry'
            .DIRECTORY_SEPARATOR.'crypt-gpg-pinentry';

        return $pinEntry;
    }

    /**
     * Displays debug text if debugging is turned on.
     *
     * Debugging text is prepended with a debug identifier and echoed to stdout.
     *
     * @param string $text the debugging text to display.
     */
    private function _debug($text)
    {
        if ($this->_debug) {
            if (php_sapi_name() === 'cli') {
                foreach (explode(PHP_EOL, $text) as $line) {
                    echo "Crypt_GPG DEBUG: ", $line, PHP_EOL;
                }
            } else {
                // running on a web server, format debug output nicely
                foreach (explode(PHP_EOL, $text) as $line) {
                    echo "Crypt_GPG DEBUG: <strong>", $line,
                        '</strong><br />', PHP_EOL;
                }
            }
        }
    }
}
