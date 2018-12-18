# usr/local/bin/python2 -*-
"""
continuously monitors files in a given directory for a given 'magic string'
and logs the location of that string continuously based on sysargs
"""
import argparse
import signal
import logging
import time
from os import listdir
from os.path import isfile, join

__author__ = "Jake Johnson"


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "interval", help="polling interval used to search for magic text")
    parser.add_argument(
        "extention", help="type of file to search for ex: '.txt' ")
    parser.add_argument(
        "magic_text", help="magic text to search for in directory")

    parser.add_argument("directory", help="directory to watch")
    return parser


def create_logger():
    # create logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter(
        '%(asctime)s  %(levelname)s:  %(message)s',
        datefmt='%Y-%m-%d  %H:%M')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    return logger


def watch_directory(directory, extention, magic_text,):
    global checked_files
    files = [f for f in listdir(directory) if isfile(
        join(directory, f)) and f.endswith(extention)]

    for f in files:
        path = directory + '/' + f
        with open(path) as file:
            if path not in checked_files.keys():
                checked_files[path] = []
            for index, line in enumerate(file.readlines()):
                if index not in checked_files[path]:
                    checked_files[path].append(index)

                    if magic_text in line:
                        logger.info(
                            '\nMatch found in {} line {}\n\n'
                            .format(f, index+1))


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
    logger.warning('\nReceived {}\n'.format(signames[sig_num]))

    exit_flag = True


def main(directory, extention, magic_text, polling_interval):

    polling_interval = float(polling_interval)
    # Hook these two signals from the OS ..
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # Now my signal_handler will get called
    # if OS sends either of these to my process.
    logger.info('\n-------------------------------------------------------'
                + '\n\t\tStarting search in {}'.format(args.directory)
                + '\n------------------------------------------------------')

    # start a timer before we begin polling
    start_time = time.time()
    while not exit_flag:
        try:
            watch_directory(directory, extention, magic_text)
        except OSError:
            logger.error("\nCouldn't find the file. Make sure the directory"
                         + " and that the file exists and try again.")
        except IOError:
            logger.error('\nFile not found.')
            # This is an UNHANDLED exception
            # Log an ERROR level message here
            # put a sleep inside my while loop
            # so I don't peg the cpu usage at 100%
        time.sleep(polling_interval)

    # final exit point happens here
    # Log a message that we are shutting down
    logger.info('\n----------------------------------------------------------'
                + '---\n\t\tTerminated Application\n\t\tTotal uptime: {} {}'
                .format(round(time.time() - start_time, 2), 'seconds')
                + '\n--------------------------------------------------------')

    exit(0)
    # Include the overall uptime since program start.


if __name__ == "__main__":
    """ This is executed when run from the command line """

    checked_files = {}
    exit_flag = False

    logger = create_logger()
    parser = create_parser()
    args = parser.parse_args()

    main(args.directory, args.extention, args.magic_text, args.interval)
