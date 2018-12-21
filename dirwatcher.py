# usr/local/bin/python2 -*-
"""
continuously monitors files in a given directory for a given 'magic string'
and logs the location of that string continuously based on sysargs
"""
import argparse
import signal
import logging
import time
from datetime import datetime
from os import listdir
from os.path import isfile, join

__author__ = "Jake Johnson"


class Error(Exception):
    """Base class for other exceptions"""
    pass


class DirectoryEmptyError(Error):
    """Raised when a directory exists but it is empty"""
    pass


def create_parser():
    """
    Create parser for command line that takes all arguments
    """
    parser = argparse.ArgumentParser("Monitor a directory for files with a "
                                     "given extention"
                                     "that contain a string of 'Magic Text' ")
    parser.add_argument(
        "magic_text", help="magic text to search for in directory")
    parser.add_argument(
        "--directory", help="directory to watch. default: root")
    parser.add_argument(
        "--extention", help="type of file to search for. default: .txt ")
    parser.add_argument(
        "--interval", help="polling interval used to search for magic text."
        "default: 5")

    return parser


def create_logger():
    """
    Settup logger level and format
    """
    # create logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    # create formatter
    formatter = logging.Formatter(
        '%(asctime)s  %(levelname)s:  %(message)s',
        datefmt='%Y-%m-%d  %H:%M:%S')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)

    return logger


def watch_directory(directory, extention, magic_text):
    """
    This function scans a directory for all files with a given extention and
    keeps track of how many times the magic_text string is found in each file
    """
    global checked_files
    matches = dict()

    files = [join(directory, f) for f in listdir(directory) if isfile(
        join(directory, f)) and f.endswith(extention)]

    if not files:
        raise DirectoryEmptyError

    for path in files:
        if path not in checked_files.keys():
            checked_files[path] = []

        with open(path) as file:
            for index, line in enumerate(file.readlines()):
                if index not in checked_files[path]:
                    checked_files[path].append(index)
                    if magic_text in line:
                        filename = path.split('/')[-1]

                        if filename in matches.keys():
                            matches[filename].append(index + 1)
                        else:
                            matches[filename] = [index + 1]

    if matches:
        for f, indexes in matches.items():
            matches_str = ''.join(['line: {}\n'.format(i)
                                   for i in indexes]).strip()
            total = len(indexes)
            logger.info('\n\n'
                        '** MATCHES FOUND **\n\n'
                        '"{}" Was Found {} Times in {}:\n\n'
                        '-----------------------------\n'
                        '{}\n'
                        '-----------------------------\n'
                        .format(magic_text, total, f, matches_str))


def signal_handler(sig_num, frame):
    """
    This is a handler for SIGTERM and SIGINT. Other signals can be mapped
    here as well (SIGHUP?)Basically it just sets a global flag, and main()
     will exit it's loop if the signal is trapped.
    :param sig_num: The integer signal number that was trapped from the OS.
    :param frame: Not used
    :return None
    """
    global exit_flag
    signames = dict((k, v) for v, k in reversed(sorted(
        signal.__dict__.items()))
        if v.startswith('SIG') and not v.startswith('SIG_'))
    logger.warning(
        '\nReceived {}\n\nShutting Down...'.format(signames[sig_num]))

    exit_flag = True


def main(directory, extention, magic_text, polling_interval):
    """
    This function calls the watch_directory() function at a given interval
    and logs information as necessary. application only closes when it recieves
    SIGINT and SIGTERM signals
    """
    polling_interval = float(polling_interval)
    # Hook these two signals from the OS ..
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # Now my signal_handler will get called
    # if OS sends either of these to my process.
    logger.info('\n'
                '-------------------------------------------------------\n'
                '\t\tStarting search in \'{}\'\n'
                '-------------------------------------------------------\n\n'
                .format(directory))
    time.sleep(.2)

    # start a timer before we begin polling
    start_time = datetime.now()
    while not exit_flag:
        try:
            watch_directory(directory, extention, magic_text)
        except DirectoryEmptyError:
            logger.warning(
                '\ndirectory exists, but no files with the extention '
                'were found\n\n')

            time.sleep(8)

        except OSError as e:
            logger.error("\nAn Error Occurred.\n"
                         "{}"
                         "Double Check that the directory exists and "
                         "try again\n".format(e))
            time.sleep(8)

        except Exception as e:
            logger.error("\nAn Error Occurred.\n"
                         "{}"
                         "Double Check that the directory exists and "
                         "try again\n".format(e))
            time.sleep(8)

        # put a sleep inside my while loop
        # so I don't peg the cpu usage at 100%
        time.sleep(polling_interval)

    # final exit point happens here
    # Log a message that we are shutting down
    running_time = datetime.now() - start_time
    logger.info('\n'
                '-------------------------------------------------------\n'
                '\t\tTerminated Application\n'
                '\t\tTotal uptime: {}\n'
                '--------------------------------------------------------'
                .format(running_time))

    exit(0)


if __name__ == "__main__":
    """ This is executed when run from the command line """

    checked_files = {}
    exit_flag = False

    logger = create_logger()
    parser = create_parser()
    args = parser.parse_args()

    directory = args.directory or '.'
    extention = args.extention or '.txt'
    interval = args.interval or 3
    main(directory, extention, args.magic_text, interval)
