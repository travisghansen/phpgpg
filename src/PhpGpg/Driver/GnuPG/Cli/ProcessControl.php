<?php
namespace PhpGpg\Driver\GnuPG\Cli;

class ProcessControl
{
    /**
     * The PID (process identifier) being monitored.
     *
     * @var integer
     */
    protected $pid;

    /**
     * Creates a new process controller from the given PID (process identifier).
     *
     * @param integer $pid the PID (process identifier).
     */
    public function __construct($pid)
    {
        $this->pid = $pid;
    }

    /**
     * Gets the PID (process identifier) being controlled.
     *
     * @return integer the PID being controlled.
     */
    public function getPid()
    {
        return $this->pid;
    }

    /**
     * Checks if the process is running.
     *
     * Uses <kbd>ps</kbd> on UNIX-like systems and <kbd>tasklist</kbd> on
     * Windows.
     *
     * @return boolean true if the process is running, false if not.
     */
    public function isRunning()
    {
        $running = false;

        if (PHP_OS === 'WINNT') {
            $command = 'tasklist /fo csv /nh /fi '
                .escapeshellarg('PID eq '.$this->pid);

            $result  = exec($command);
            $parts   = explode(',', $result);
            $running = (count($parts) > 1 && trim($parts[1], '"') == $this->pid);
        } else {
            $result  = exec('ps -p '.escapeshellarg($this->pid).' -o pid=');
            $running = (trim($result) == $this->pid);
        }

        return $running;
    }

    /**
     * Ends the process gracefully.
     *
     * The signal SIGTERM is sent to the process. The gpg-agent process will
     * end gracefully upon receiving the SIGTERM signal. Upon 3 consecutive
     * SIGTERM signals the gpg-agent will forcefully shut down.
     *
     * If the <kbd>posix</kbd> extension is available, <kbd>posix_kill()</kbd>
     * is used. Otherwise <kbd>kill</kbd> is used on UNIX-like systems and
     * <kbd>taskkill</kbd> is used in Windows.
     */
    public function terminate()
    {
        if (function_exists('posix_kill')) {
            posix_kill($this->pid, 15);
        } elseif (PHP_OS === 'WINNT') {
            exec('taskkill /PID '.escapeshellarg($this->pid));
        } else {
            exec('kill -15 '.escapeshellarg($this->pid));
        }
    }
}
