# usr/local/bin/python2 -*-
"""
Module Docstring
"""
import argparse
import signal
import logging
import time
from os import listdir
from os.path import isfile, join

__author__ = "Jake Johnson"


exit_flag = False
logger = logging


def watch_directory(directory, extention, magic_text,):
    files = [f for f in listdir(directory) if isfile(
        join(directory, f)) and f.endswith(extention)]

    for f in files:
        with open(directory + '/' + f) as file:
            for index, line in enumerate(file.readlines()):
                if magic_text in line:
                    print('Match found in {} line {}'.format(f, index+1))


def signal_handler(sig_num, frame):
    """
    This is a handler for SIGTERM and SIGINT. Other signals can be mapped
    here as well (SIGHUP?)Basically it just sets a global flag, and main()
     will exit it's loop if the signal is trapped.
    :param sig_num: The integer signal number that was trapped from the OS.
    :param frame: Not used
    :return None
    """
    signames = dict((k, v) for v, k in reversed(sorted(
        signal.__dict__.items()))
        if v.startswith('SIG') and not v.startswith('SIG_'))
    logger.error('Received {}'.format(signames[sig_num]))
    global exit_flag
    exit_flag = True


def main(directory, extention, magic_text, polling_interval):
    polling_interval = float(polling_interval)
    # Hook these two signals from the OS ..
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # Now my signal_handler will get called
    #  if OS sends either of these to my process.

    while not exit_flag:
        try:
            watch_directory(directory, extention, magic_text)
        except Exception as e:
            # This is an UNHANDLED exception
            # Log an ERROR level message here
            logger.error(e)
            # put a sleep inside my while loop
            # so I don't peg the cpu usage at 100%
        time.sleep(polling_interval)

    # final exit point happens here
    # Log a message that we are shutting down
    logger.log('Shutting down...')
    # Include the overall uptime since program start.


if __name__ == "__main__":
    """ This is executed when run from the command line """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "interval", help="polling interval used to search for magic text")
    parser.add_argument(
        "extention", help="type of file to search for ex: '.txt' ")
    parser.add_argument(
        "magic_text", help="magic text to search for in directory")

    parser.add_argument("directory", help="directory to watch")

    args = parser.parse_args()
    main(args.directory, args.extention, args.magic_text, args.interval)
