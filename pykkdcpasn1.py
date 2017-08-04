#!/usr/bin/python3
"""Kerberos 5 / MS-KKDCP ASN.1

See RFC 4120, Appendix A, https://tools.ietf.org/html/rfc4120#appendix-A

KerberosV5Spec2 {
        iso(1) identified-organization(3) dod(6) internet(1)
        security(5) kerberosV5(2) modules(4) krb5spec2(2)
} DEFINITIONS EXPLICIT TAGS ::= BEGIN

"""
import struct

from asn1crypto import core

# KerberosV5Spec2 DEFINITIONS EXPLICIT TAGS ::=
TAG = 'explicit'

# class
APPLICATION = 1

# strict parsing w/o trailing bytes
STRICT = True


class Int32(core.Integer):
    """Int32 ::= INTEGER (-2147483648..2147483647)
    """


class UInt32(core.Integer):
    """UInt32 ::= INTEGER (0..4294967295)
    """


class KerberosString(core.GeneralString):
    """KerberosString ::= GeneralString (IA5String)

    For compatibility, implementations MAY choose to accept GeneralString
    values that contain characters other than those permitted by
    IA5String...
    """


class SequenceOfKerberosString(core.SequenceOf):
    """SEQUENCE OF KerberosString
    """
    _child_spec = KerberosString


class Realm(KerberosString):
    """Realm ::= KerberosString
    """


class PrincipalName(core.Sequence):
    """PrincipalName for KDC-REQ-BODY and Ticket
    PrincipalName ::= SEQUENCE {
        name-type    [0] Int32,
        name-string  [1] SEQUENCE OF KerberosString
    }
    """
    _fields = [
        ('name-type', Int32, {'tag_type': TAG, 'tag': 0}),
        ('name-string', SequenceOfKerberosString, {'tag_type': TAG, 'tag': 1}),
    ]


class KerberosTime(core.GeneralizedTime):
    """KerberosTime ::= GeneralizedTime
    """


class HostAddress(core.Sequence):
    """HostAddress for HostAddresses

    HostAddress ::= SEQUENCE {
        addr-type        [0] Int32,
        address  [1] OCTET STRING
    }
    """
    _fields = [
        ('addr-type', Int32, {'tag_type': TAG, 'tag': 0}),
        ('address', core.OctetString, {'tag_type': TAG, 'tag': 1}),
    ]


class HostAddresses(core.SequenceOf):
    """HostAddresses for KDC-REQ-BODY

    HostAddresses ::= SEQUENCE OF HostAddress
    """
    _child_spec = HostAddress


class PA_DATA(core.Sequence):
    """PA-DATA for KDC-REQ

    PA-DATA ::= SEQUENCE {
        padata-type  [1] int32,
        pa-data      [2] OCTET STRING
    }
    """
    _fields = [
        # NOTE: first tag is [1], not [0]
        ('padata-type', Int32, {'tag_type': TAG, 'tag': 1}),
        ('pa-data', core.OctetString, {'tag_type': TAG, 'tag': 2}),
    ]


class SequenceOfPA_DATA(core.SequenceOf):
    """SEQUENCE OF PA-DATA
    """
    _child_spec = PA_DATA


class EncryptedData(core.Sequence):
    """EncryptedData

    * KDC-REQ-BODY
    * Ticket
    * AP-REQ
    * KRB-PRIV

    EncryptedData ::= SEQUENCE {
        etype        [0] Int32,
        kvno         [1] UInt32 OPTIONAL,
        cipher       [2] OCTET STRING
    }
    """
    _fields = [
        ('etype', Int32, {'tag_type': TAG, 'tag': 0}),
        ('kvno', UInt32, {'tag_type': TAG, 'tag': 1, 'optional': True}),
        ('cipher', core.OctetString, {'tag_type': TAG, 'tag': 2}),
    ]


class Ticket(core.Sequence):
    """Ticket for AP-REQ and SEQUENCE OF Ticket

    Ticket ::= [APPLICATION 1] SEQUENCE {
        tkt-vno      [0] INTEGER,
        realm        [1] Realm,
        sname        [2] PrincipalName,
        enc-part     [3] EncryptedData
    }
    """
    explicit_class = APPLICATION
    explicit_tag = 1
    tag_type = TAG

    _fields = [
        ('tkt-vno', core.Integer, {'tag_type': TAG, 'tag': 0}),
        ('realm', Realm, {'tag_type': TAG, 'tag': 1}),
        ('sname', PrincipalName, {'tag_type': TAG, 'tag': 2}),
        ('enc-part', EncryptedData, {'tag_type': TAG, 'tag': 3}),
    ]


class KDCOptions(core.BitString):
    """KDCOptions for KDC-REQ-BODY

    KDCOptions ::= BIT STRING {
        reserved(0),
        forwardable(1),
        forwarded(2),
        proxiable(3),
        proxy(4),
        allow-postdate(5),
        postdated(6),
        unused7(7),
        renewable(8),
        unused9(9),
        unused10(10),
        opt-hardware-auth(11),
        unused12(12),
        unused13(13),
        -- 15 is reserved for canonicalize
        unused15(15),
        -- 26 was unused in 1510
        disable-transited-check(26),
        renewable-ok(27),
        enc-tkt-in-skey(28),
        renew(30),
        validate(31)
    }
    """
    _map = {
        0: 'reserved',
        1: 'forwardable',
        2: 'forwarded',
        3: 'proxiable',
        4: 'proxy',
        5: 'allow-postdate',
        6: 'postdated',
        7: 'unused7',
        8: 'renewable',
        9: 'unused9',
        10: 'ununsed10',
        11: 'opt-hardware-auth',
        12: 'ununsed12',
        13: 'ununsed13',
        15: 'ununsed15',
        26: 'disable-transited-check',
        27: 'renewable-ok',
        29: 'enc-tkt-in-skey',
        30: 'renew',
        31: 'validate',
    }


class SequenceOfTicket(core.SequenceOf):
    """SEQUENCE OF Ticket for KDC-REQ-BODY
    """
    _child_spec = Ticket


class SequenceOfInt32(core.SequenceOf):
    """SEQUENCE OF Int32 for KDC-REQ-BODY
    """
    _child_spec = Int32


class KDC_REQ_BODY(core.Sequence):
    """
    KDC-REQ-BODY ::= SEQUENCE {
        kdc-options  [0] KDCOptions,
        cname        [1] PrincipalName OPTIONAL
                         -- Used only in AS-REQ --,
        realm        [2] Realm,
                         -- Server's realm
                         -- Also client's in AS-REQ --,
        sname        [3] PrincipalName OPTIONAL,
        from         [4] KerberosTime OPTIONAL,
        till         [5] KerberosTime,
        rtime        [6] KerberosTime OPTIONAL,
        nonce        [7] UInt32,
        etype        [8] SEQUENCE OF Int32,
                         -- Int32 in preference order --,
        addresses    [9] HostAddresses OPTIONAL,
        enc-authorization-data       [10] EncryptedData OPTIONAL,
                                          -- AuthorizationData --,
        additional-tickets   [11] SEQUENCE OF Ticket OPTIONAL
                                  -- NOTE: not empty
    }
    """
    _fields = [
        ('kdc-options', KDCOptions, {'tag_type': TAG, 'tag': 0}),
        ('cname', PrincipalName, {'tag_type': TAG, 'tag': 1, 'optional': True}),
        ('realm', Realm, {'tag_type': TAG, 'tag': 2}),
        ('sname', PrincipalName, {'tag_type': TAG, 'tag': 3, 'optional': True}),
        ('from', KerberosTime, {'tag_type': TAG, 'tag': 4, 'optional': True}),
        ('till', KerberosTime, {'tag_type': TAG, 'tag': 5}),
        ('rtime', KerberosTime, {'tag_type': TAG, 'tag': 6, 'optional': True}),
        ('nonce', UInt32, {'tag_type': TAG, 'tag': 7}),
        ('etype', SequenceOfInt32, {'tag_type': TAG, 'tag': 8}),
        ('addresses', HostAddresses,
         {'tag_type': TAG, 'tag': 9, 'optional': True}),
        ('enc-authorization-data', EncryptedData,
         {'tag_type': TAG, 'tag': 10, 'optional': True}),
        ('additional-tickets', SequenceOfTicket,
         {'tag_type': TAG, 'tag': 11, 'optional': True}),
    ]


class KDC_REQ(core.Sequence):
    """KDC-REQ, base of AS-REQ and TGS-REQ

    KDC-REQ ::= SEQUENCE {
        pvno         [1] INTEGER (5),
        msg-type     [2] INTEGER (10 -- AS -- | 12 -- TGS --),
        padata       [3] SEQUENCE OF PA-DATA OPTIONAL,
                         -- NOTE: not empty --,
        req-body     [4] KDC-REQ-BODY
    }
    """
    _fields = [
        # NOTE: first tag is [1], not [0]
        ('pvno', core.Integer, {'tag_type': TAG, 'tag': 1, 'default': 5}),
        ('msg-type', core.Integer, {'tag_type': TAG, 'tag': 2}),
        ('padata', SequenceOfPA_DATA, {'tag_type': TAG, 'tag': 3, 'optional': True}),
        ('req-body', KDC_REQ_BODY, {'tag_type': TAG, 'tag': 4}),
    ]


class AS_REQ(KDC_REQ):
    """AS-REQ -- Authentication service request

    AS-REQ ::= [APPLICATION 10] KDC-REQ
    """
    explicit_class = APPLICATION
    explicit_tag = 10
    tag_type = TAG


class TGS_REQ(KDC_REQ):
    """TGS-REQ -- Ticket-granting service request

    TGS-REQ ::= [APPLICATION 12] KDC-REQ
    """
    explicit_class = APPLICATION
    explicit_tag = 12
    tag_type = TAG


class APOptions(core.BitString):
    """APOptions for AP-REQ

    APOptions ::= BIT STRING {
        reserved(0),
        use-session-key(1),
        mutual-required(2)
    }
    """
    _map = {
        0: 'reserved',
        1: 'use-session-key',
        2: 'mutual-required',
    }


class AP_REQ(core.Sequence):
    """AP-REQ -- Application request

    Client/server authentication exchange (CS)

    AP-REQ ::= [APPLICATION 14] SEQUENCE {
        pvno         [0] INTEGER (5),
        msg-type     [1] INTEGER (14),
        ap-options   [2] APOptions,
        ticket       [3] Ticket,
        authenticator        [4] EncryptedData
    }
    """
    explicit_class = APPLICATION
    explicit_tag = 14
    tag_type = TAG

    _fields = [
        ('pvno', core.Integer, {'tag_type': TAG, 'tag': 0, 'default': 5}),
        ('msg-type', core.Integer, {'tag_type': TAG, 'tag': 1, 'default': 14}),
        ('ap-options', APOptions, {'tag_type': TAG, 'tag': 2}),
        ('ticket', Ticket, {'tag_type': TAG, 'tag': 3}),
        ('authenticator', EncryptedData, {'tag_type': TAG, 'tag': 4}),
    ]


class KRB_PRIV(core.Sequence):
    """KRB-PRIV

    KRB-PRIV ::= [APPLICATION 21] SEQUENCE {
        pvno         [0] INTEGER (5),
        msg-type     [1] INTEGER (21),
        enc-part     [3] EncryptedData
    }
    """
    explicit_class = APPLICATION
    explicit_tag = 21
    tag_type = TAG

    _fields = [
        ('pvno', core.Integer, {'tag_type': TAG, 'tag': 0, 'default': 5}),
        ('msg-type', core.Integer, {'tag_type': TAG, 'tag': 1, 'default': 21}),
        # NOTE: there is no [2] tag
        ('enc-part', EncryptedData, {'tag_type': TAG, 'tag': 3}),
    ]


class KDC_PROXY_MESSAGE(core.Sequence):
    """Kerberos Key Distribution Center (KDC) Proxy Protocol (KKDCP)

    [MS-KKDCP], 2.2.2

    KDC-PROXY-MESSAGE ::= SEQUENCE {
        kerb-message         [0] OCTET STRING,
        target-domain        [1] Realm OPTIONAL,
        dclocator-hint       [2] INTEGER OPTIONAL
    }
    """
    _fields = [
        ('kerb-message', core.OctetString, {'tag_type': TAG, 'tag': 0}),
        ('target-domain', Realm, {'tag_type': TAG, 'tag': 1, 'optional': True}),
        ('dclocator-hint', core.Integer, {'tag_type': TAG, 'tag': 2, 'optional': True}),
    ]

    @property
    def kerb_message(self):
        return self['kerb-message'].native

    @property
    def target_domain(self):
        return self['target-domain'].native

    @property
    def dclocator_hint(self):
        return self['dclocator-hint'].native


def ntohlb(b):
    """"ntohl for bytes[4]
    """
    return struct.unpack('!i', b)[0]


def ntohsb(b):
    """ntohs for bytes[2]
    """
    return struct.unpack('!h', b)[0]


def decode_outer(outer_msg):
    kdc_msg = KDC_PROXY_MESSAGE.load(outer_msg, strict=STRICT)

    kerb_msg = kdc_msg.kerb_message
    if len(kerb_msg) < 4:
        raise ValueError('kerb_message < 4')
    msglen = ntohlb(kerb_msg[:4])
    if msglen + 4 != len(kerb_msg):
        raise ValueError("msglen mismatch {} + 4 != {}".format(
            msglen, len(kerb_msg)))

    return kerb_msg, kdc_msg.target_domain, kdc_msg.dclocator_hint


def decode_asreq(inner_msg):
    """AS-REQ

    0..3: length of inner message
    4..end: AS-REQ
    """
    asreq = AS_REQ.load(inner_msg[4:], strict=STRICT)
    asreq.native  # parse children
    return asreq


def decode_tgsreq(inner_msg):
    """TGS-REQ

    0..3: length of inner message
    4..end: TGS-REQ
    """
    tgsreq = TGS_REQ.load(inner_msg[4:], strict=STRICT)
    tgsreq.native  # parse children
    return tgsreq


def decode_apreq_krb_priv(inner_msg):
    """kpasswd request

    The request is a bit more complicated than the others

    0..3: length of inner message
    4..5: length, end of KRB-PRIV part
    6..7: password change request version
    8..9: AP-REQ len
    10..apreq: AP-REQ
    apreq..end: KRB-PRIV
    """
    # 0..3 are total length of inner message, already verified
    buflen = len(inner_msg) - 4

    # 4..5, length of kpasswd
    kpasswd_len = ntohsb(inner_msg[4:6])
    if kpasswd_len != buflen or kpasswd_len < 9:
        raise ValueError("kpasswd len {} != {}".format(
            kpasswd_len, buflen))
    buflen -= 2

    # 6..7, password change request version
    version = ntohsb(inner_msg[6:8])
    if version not in (0x0001, 0xff80):
        raise ValueError("Invalid kpasswd version 0x{:03x}".format(version))
    buflen -= 2

    # 8..9, length of inner AP-REQ
    apreq_len = ntohsb(inner_msg[8:10])
    if apreq_len > buflen:
        raise ValueError("apreq len {} > {}".format(apreq_len, buflen))
    buflen -= 2
    apreq = AP_REQ.load(inner_msg[10:10+apreq_len], strict=STRICT)
    # apreq.native # parse children
    krbpriv = KRB_PRIV.load(inner_msg[10 + apreq_len:], strict=STRICT)
    # krbpriv.native # parse children
    return apreq, krbpriv


request_decoders = [
    (u'asreq', decode_asreq),
    (u'tgsreq', decode_tgsreq),
    (u'kpasswd', decode_apreq_krb_priv),
]


def test():
    from pprint import pprint

    with open('testcases/asreq1.der', 'rb') as f:
        asreq_der = f.read()

    inner_msg, realm, dclocator = decode_outer(asreq_der)
    asreq = decode_asreq(inner_msg)
    pprint(asreq.native)

    with open('testcases/tgsreq.der', 'rb') as f:
        tgsreq_der = f.read()

    inner_msg, realm, dclocator = decode_outer(tgsreq_der)
    tgsreq = decode_tgsreq(inner_msg)
    pprint(tgsreq.native)

    with open('testcases/kpasswdreq.der', 'rb') as f:
        kpasswd_der = f.read()

    inner_msg, realm, dclocator = decode_outer(kpasswd_der)
    apreq, krbpriv = decode_apreq_krb_priv(inner_msg)
    pprint(krbpriv.native)
    pprint(apreq.native)


if __name__ == '__main__':
    test()
