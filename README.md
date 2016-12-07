# ASN.1 parser for KKDCP (Kerberos KDC Proxy)

[![Build Status](https://travis-ci.org/tiran/kkdcpasn1.svg?branch=master)](https://travis-ci.org/tiran/kkdcpasn1)

Christian Heimes <cheimes@redhat.com>


## Parse request

```
>>> import kkdcpasn1
>>> asreq1 = b'''0\x81\xc4\xa0\x81\xb0\x04\x81\xad\x00\x00\x00\xa9j\
\x81\xa60\x81\xa3\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\n\xa3\x0e0\x0c\
0\n\xa1\x04\x02\x02\x00\x95\xa2\x02\x04\x00\xa4\x81\x860\x81\x83\xa0\
\x07\x03\x05\x00@\x00\x00\x10\xa1\x120\x10\xa0\x03\x02\x01\x01\xa1\
\t0\x07\x1b\x05admin\xa2\x0f\x1b\rFREEIPA.LOCAL\xa3"0 \xa0\x03\x02\
\x01\x02\xa1\x190\x17\x1b\x06krbtgt\x1b\rFREEIPA.LOCAL\xa5\x11\x18\
\x0f20150514104238Z\xa7\x06\x02\x04\x11\xc8c\xb5\xa8\x140\x12\x02\x01\
\x12\x02\x01\x11\x02\x01\x10\x02\x01\x17\x02\x01\x19\x02\x01\x1a\xa1\
\x0f\x1b\rFREEIPA.LOCAL'''
>>> result = kkdcpasn1.decode_kkdcp_request(asreq1)
>>> result.realm
'FREEIPA.LOCAL'
>>> result.dclocator_hint
0
>>> result.request_type
'asreq'
>>> result.consumed
169
>>> result.offset
4
>>> result.request
...
```

## Wrap response

```
>>> import kkdcpasn1
>>> wrapped = kkdcpasn1.wrap_kkdcp_response(tcp_data)
>>> wrapped = kkdcpasn1.wrap_kkdcp_response(udp_data, add_prefix=True)
```