#!/usr/bin/env python3
from __future__ import print_function

import os
import time

import psutil

import kkdcpasn1

HERE = os.path.dirname(os.path.abspath(__file__))
TESTCASES = os.path.abspath(os.path.join(HERE, os.pardir, 'testcases'))


def check(loops=333333):
    with open(os.path.join(TESTCASES, 'asreq2.der'), 'rb') as f:
        asreq2 = f.read()
    with open(os.path.join(TESTCASES, 'tgsreq.der'), 'rb') as f:
        tgsreq = f.read()
    with open(os.path.join(TESTCASES, 'kpasswdreq.der'), 'rb') as f:
        kpasswdreq = f.read()

    decode_kkdcp_request = kkdcpasn1.decode_kkdcp_request
    wrap_kkdcp_response = kkdcpasn1.wrap_kkdcp_response

    # first run
    decode_kkdcp_request(asreq2)
    decode_kkdcp_request(tgsreq)
    result = decode_kkdcp_request(kpasswdreq)
    wrap_kkdcp_response(result.request, True)

    print("\n*** Running memory and timing tests")
    p = psutil.Process(os.getpid())
    meminfo = p.memory_info()
    print("Before:", meminfo)

    start = time.monotonic()
    for _ in range(loops):
        result = decode_kkdcp_request(asreq2)
        wrap_kkdcp_response(result.request, True)
        result = decode_kkdcp_request(tgsreq)
        wrap_kkdcp_response(result.request, True)
        result = decode_kkdcp_request(kpasswdreq)
        wrap_kkdcp_response(result.request, True)
    total = time.monotonic() - start

    meminfo2 = p.memory_info()
    print("After: ", meminfo2)
    print("{:0.3f} secs for {} loops". format(total, loops*3))
    if meminfo2.rss > meminfo.rss + 1024**2:
        raise MemoryError

if __name__ == "__main__":
    check()
