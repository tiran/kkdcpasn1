/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "KKDCP"
 * 	found in "kkdcp.asn1"
 */

#include "KRB-PRIV.h"

static asn_TYPE_member_t asn_MBR_KRB_PRIV_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct KRB_PRIV, pvno),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"pvno"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct KRB_PRIV, msg_type),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"msg-type"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct KRB_PRIV, enc_part),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_EncryptedData,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"enc-part"
		},
};
static ber_tlv_tag_t asn_DEF_KRB_PRIV_tags_1[] = {
	(ASN_TAG_CLASS_APPLICATION | (21 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_KRB_PRIV_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* pvno */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* msg-type */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 2, 0, 0 } /* enc-part */
};
static asn_SEQUENCE_specifics_t asn_SPC_KRB_PRIV_specs_1 = {
	sizeof(struct KRB_PRIV),
	offsetof(struct KRB_PRIV, _asn_ctx),
	asn_MAP_KRB_PRIV_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_KRB_PRIV = {
	"KRB-PRIV",
	"KRB-PRIV",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_KRB_PRIV_tags_1,
	sizeof(asn_DEF_KRB_PRIV_tags_1)
		/sizeof(asn_DEF_KRB_PRIV_tags_1[0]), /* 2 */
	asn_DEF_KRB_PRIV_tags_1,	/* Same as above */
	sizeof(asn_DEF_KRB_PRIV_tags_1)
		/sizeof(asn_DEF_KRB_PRIV_tags_1[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_KRB_PRIV_1,
	3,	/* Elements count */
	&asn_SPC_KRB_PRIV_specs_1	/* Additional specs */
};

