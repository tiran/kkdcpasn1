from libc.stdint cimport uint8_t, uint16_t, uint32_t
from libc.string cimport memcpy, memset
from libc.stdlib cimport malloc, free
from libc.stdio cimport FILE, stderr
from cpython.version cimport PY_MAJOR_VERSION

if PY_MAJOR_VERSION >= 3:
    text = str
else:
    text = unicode


cdef extern from "arpa/inet.h":
    uint32_t ntohl(uint32_t)
    uint32_t htonl(uint32_t)
    uint16_t ntohs(uint16_t)


cdef extern from "asn_codecs.h":
    int RC_OK
    int RC_WMORE
    int RC_FAIL

    ctypedef struct asn_enc_rval_t:
        int code
        size_t encoded

    ctypedef struct asn_dec_rval_t:
        int code
        size_t consumed


cdef extern from "constr_TYPE.h":
    ctypedef struct asn_TYPE_descriptor_t:
        pass

    ctypedef struct asn_codec_ctx_t:
        pass

    cdef void ASN_STRUCT_FREE(asn_TYPE_descriptor_t, void *)
    cdef void ASN_STRUCT_FREE_CONTENTS_ONLY(asn_TYPE_descriptor_t, void *)


cdef extern from "ber_decoder.h":
    cdef asn_dec_rval_t ber_decode(
        asn_codec_ctx_t *,
        asn_TYPE_descriptor_t *,
        void **,
        void *,
        size_t
    )


cdef extern from "der_encoder.h":
    cdef asn_enc_rval_t der_encode(
        asn_TYPE_descriptor_t *,
        void *,
        void *,  # asn_app_consume_bytes_f
        void *
    )

    cdef asn_enc_rval_t der_encode_to_buffer(
        asn_TYPE_descriptor_t *,
        void *,
        void *,
        size_t
    )


cdef extern from "OCTET_STRING.h":
    ctypedef struct OCTET_STRING_t:
        uint8_t *buf
        int size

    cdef int OCTET_STRING_fromBuf(OCTET_STRING_t *, const char *, int)


cdef extern from "Realm.h":
    ctypedef OCTET_STRING_t Realm_t


cdef extern from "KDC-PROXY-MESSAGE.h":
    ctypedef struct KDC_PROXY_MESSAGE_t:
        OCTET_STRING_t kerb_message
        Realm_t *target_domain
        long dclocator_hint

    cdef asn_TYPE_descriptor_t asn_DEF_KDC_PROXY_MESSAGE


cdef extern from "AP-REQ.h":
    ctypedef struct AP_REQ_t:
        pass

    cdef asn_TYPE_descriptor_t asn_DEF_AP_REQ


cdef extern from "AS-REQ.h":
    ctypedef struct AS_REQ_t:
        pass

    cdef asn_TYPE_descriptor_t asn_DEF_AS_REQ


cdef extern from "TGS-REQ.h":
    ctypedef struct TGS_REQ_t:
        pass

    cdef asn_TYPE_descriptor_t asn_DEF_TGS_REQ


cdef decode_outer(bytes outer_msg):
    cdef asn_dec_rval_t rval
    cdef KDC_PROXY_MESSAGE_t *kkdcp_msg = NULL
    cdef uint8_t *buf = outer_msg
    cdef uint32_t msglen
    cdef bytes inner_msg
    cdef long dclocator_hint

    rval = ber_decode(
        NULL,
        &asn_DEF_KDC_PROXY_MESSAGE,
        <void **>&kkdcp_msg,
        <void *>buf,
        len(outer_msg)
    )

    if rval.code != RC_OK:
        ASN_STRUCT_FREE(asn_DEF_KDC_PROXY_MESSAGE, kkdcp_msg)
        raise ValueError(rval.code, rval.consumed)

    if kkdcp_msg.kerb_message.size < 4:
        ASN_STRUCT_FREE(asn_DEF_KDC_PROXY_MESSAGE, kkdcp_msg)
        raise ValueError('kerb_message < 4')

    # kkdcp_msg.kerb_message.buf[0:4]
    memcpy(&msglen, kkdcp_msg.kerb_message.buf, 4)
    msglen = ntohl(msglen)
    if msglen + 4 != kkdcp_msg.kerb_message.size:
        ASN_STRUCT_FREE(asn_DEF_KDC_PROXY_MESSAGE, kkdcp_msg)
        raise ValueError("msglen mismatch {} + 4 != {}".format(
            msglen, kkdcp_msg.kerb_message.size))

    inner_msg = <bytes>kkdcp_msg.kerb_message.buf[:msglen+4]

    if kkdcp_msg.target_domain:
        realm = kkdcp_msg.target_domain.buf[:kkdcp_msg.target_domain.size]
    else:
        realm = None

    dclocator_hint = kkdcp_msg.dclocator_hint
    ASN_STRUCT_FREE(asn_DEF_KDC_PROXY_MESSAGE, kkdcp_msg)

    return inner_msg, realm, dclocator_hint


cdef object decode_asreq(bytes inner_msg):
    cdef asn_dec_rval_t rval
    cdef AS_REQ_t *as_req = NULL
    cdef uint8_t *buf = inner_msg
    cdef size_t buflen = len(inner_msg)

    # 0..3 are total length of inner message, already verified
    buf += 4
    buflen -= 4

    rval = ber_decode(
        NULL,
        &asn_DEF_AS_REQ,
        <void **>&as_req,
        <void *>buf,
        buflen
    )
    ASN_STRUCT_FREE(asn_DEF_AS_REQ, as_req)
    return rval.code, rval.consumed, 4, 0


cdef object decode_tgsreq(bytes inner_msg):
    cdef asn_dec_rval_t rval
    cdef TGS_REQ_t *tgs_req = NULL
    cdef uint8_t *buf = inner_msg
    cdef size_t buflen = len(inner_msg)

    # 0..3 are total length of inner message, already verified
    buf += 4
    buflen -= 4

    rval = ber_decode(
        NULL,
        &asn_DEF_TGS_REQ,
        <void **>&tgs_req,
        <void *>buf,
        buflen
    )
    ASN_STRUCT_FREE(asn_DEF_TGS_REQ, tgs_req)
    return rval.code, rval.consumed, 4, 0


cdef object decode_apreq(bytes inner_msg):
    cdef asn_dec_rval_t rval
    cdef AP_REQ_t *ap_req = NULL
    cdef uint8_t *buf = inner_msg
    cdef size_t buflen = len(inner_msg)
    cdef uint16_t kpasswd_len, version, apreq_len

    # 0..3 are total length of inner message, already verified
    buf += 4
    buflen -= 4

    # 4..5, length of kpasswd
    memcpy(&kpasswd_len, buf, 2)
    kpasswd_len = ntohs(kpasswd_len)
    if kpasswd_len < 6 or kpasswd_len != buflen:
        raise ValueError("kpasswd len {} != {}".format(
            kpasswd_len, buflen))
    buf += 2
    buflen -= 2

    # 6..7, password change request version
    memcpy(&version, buf, 2)
    version = ntohs(version)
    if version not in (0x0001, 0xff80):
        raise ValueError("Invalid kpasswd version 0x{:03x}".format(version))
    buf += 2
    buflen -= 2

    # 8..9, length of inner AP-REQ
    memcpy(&apreq_len, buf, 2)
    apreq_len = ntohs(apreq_len)
    if apreq_len > buflen:
        raise ValueError("apreq len {} > {}".format(apreq_len, buflen))
    buf += 2
    buflen = apreq_len

    # 10..apreq_len
    rval = ber_decode(
        NULL,
        &asn_DEF_AP_REQ,
        <void **>&ap_req,
        <void *>buf,
        buflen
    )
    ASN_STRUCT_FREE(asn_DEF_AP_REQ, ap_req)
    return rval.code, rval.consumed, 10, version


cdef class KKDCPRequest(object):
    cdef public realm
    cdef public long dclocator_hint
    cdef public bytes request
    cdef public request_type
    cdef public size_t consumed
    cdef public size_t offset
    cdef public uint32_t version

    def __init__(self, realm, long dclocator_hint, bytes request,
                 request_type, size_t consumed, size_t offset,
                 uint32_t version):
        self.realm = realm
        self.dclocator_hint = dclocator_hint
        self.request = request
        self.request_type = request_type
        self.consumed = consumed
        self.offset = offset
        self.version = version

    def __richcmp__(self, other, int op):
        if not isinstance(other, KKDCPRequest) or op not in (2, 3):
            return NotImplemented

        eq = (
            self.realm == other.realm and
            self.request == other.request and
            self.dclocator_hint == other.dclocator_hint
        )
        if op == 2:
            return eq
        else:
            return not eq

    def __hash__(self):
        return hash((self.realm, self.request, self.dclocator_hint))

    def __repr__(self):
        msg = ("<KKDCPRequest realm='{self.realm}' "
               "request_type='{self.request_type}' size={self.consumed}>")
        return msg.format(self=self)


# apreq for kpasswd must come last!
cdef list request_decoders = [
    (u'asreq', decode_asreq),
    (u'tgsreq', decode_tgsreq),
    (u'apreq', decode_apreq),
]


def decode_kkdcp_request(bytes outer_msg):
    """Decode a KKDCP request from a client

    The function decodes a KDC-PROXY-MESSAGE request and returns a
    KKDCPRequest object with realm, dclocator hint, inner message and type
    of the inner message. The type is one of 'asreq', 'tgsreq' or 'apreq'.
    For 'apreq' the version attribute holds the kpasswd version.
    """
    cdef bytes request
    cdef long dclocator_hint
    cdef int code, version
    cdef size_t consumed, offset

    request, realm, dclocator_hint = decode_outer(outer_msg)
    realm = realm.decode('utf-8')
    request_type = None
    for request_type, decoder in request_decoders:
        code, consumed, offset, version = decoder(request)
        if code == RC_OK:
            return KKDCPRequest(
                realm, dclocator_hint, request, request_type, consumed,
                offset, version)

    raise ValueError("Invalid inner message")


def wrap_kkdcp_response(bytes response_msg, add_prefix=False):
    """Encode a KKDCP response from server

    The encoder wraps a Kerberos response into a KDC-PROXY-MESSAGE.
    """
    cdef KDC_PROXY_MESSAGE_t kkdcp_msg
    cdef asn_enc_rval_t rval
    cdef uint8_t *buf = NULL
    cdef uint32_t nmsglen
    cdef char[4] nmsglenbuf
    cdef size_t buflen
    cdef int result
    cdef bytes response

    if add_prefix:
        nmsglen = htonl(len(response_msg))
        memcpy(nmsglenbuf, &nmsglen, 4)
        response_msg = nmsglenbuf[:4] + response_msg

    # response does not use target-domain.
    memset(&kkdcp_msg, 0, sizeof(KDC_PROXY_MESSAGE_t))
    result = OCTET_STRING_fromBuf(
        &kkdcp_msg.kerb_message, response_msg, len(response_msg)
    )
    if result != 0:
        raise RuntimeError("OCTET_STRING kerb_message")

    # calculate response buffer size
    rval = der_encode(
        &asn_DEF_KDC_PROXY_MESSAGE, &kkdcp_msg, NULL, NULL
    )
    if rval.encoded == -1:
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_KDC_PROXY_MESSAGE, &kkdcp_msg)
        raise RuntimeError("der_encode()")

    # malloc and encode response, allocate extra 4 bytes for length prefix
    buflen = rval.encoded
    buf = <uint8_t *>malloc(buflen)
    if buf is NULL:
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_KDC_PROXY_MESSAGE, &kkdcp_msg)
        raise MemoryError

    rval = der_encode_to_buffer(
        &asn_DEF_KDC_PROXY_MESSAGE,
        &kkdcp_msg,
        buf,
        buflen
    )
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_KDC_PROXY_MESSAGE, &kkdcp_msg)
    if rval.encoded == -1:
        free(buf)
        raise RuntimeError("der_encode_to_buffer()")

    response = <bytes>buf[:buflen]
    free(buf)
    return response
