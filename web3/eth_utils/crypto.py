from __future__ import absolute_import

from .string import (
    force_bytes,
)

import logging

try:
    from sha3 import keccak_256
    logging.debug('[keccak]>sha3')
except ImportError as e:
    logging.debug('[keccak]>sha3: %s' % e)
    try:
        from ..keccak.py_keccak import Sha3_256
        logging.debug('[keccak]>py-keccak')
        def keccak_256(*args, **kwargs):
            return force_bytes(Sha3_256(*args, **kwargs).digest())
    except ImportError as e:
        logging.debug('[keccak]>py-keccak: %s' % e)
        from ..keccak.CompactFIPS202 import SHA3_256 as keccak_256
        logging.debug('[keccak]>CompactFIPS202')

def keccak(value):
    return keccak_256(force_bytes(value))

# ensure we have the *correct* hash function
# logging.debug("[ASSERT] keccak('') = %s" % repr(keccak('')))
# assert keccak('') == b"\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p"  # noqa: E501
