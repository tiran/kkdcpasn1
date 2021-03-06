/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "KKDCP"
 * 	found in "kkdcp.asn1"
 */

#include "KDC-REQ.h"

static asn_TYPE_member_t asn_MBR_padata_4[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_PA_DATA,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static const ber_tlv_tag_t asn_DEF_padata_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_padata_specs_4 = {
	sizeof(struct padata),
	offsetof(struct padata, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_padata_4 = {
	"padata",
	"padata",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_padata_tags_4,
	sizeof(asn_DEF_padata_tags_4)
		/sizeof(asn_DEF_padata_tags_4[0]), /* 2 */
	asn_DEF_padata_tags_4,	/* Same as above */
	sizeof(asn_DEF_padata_tags_4)
		/sizeof(asn_DEF_padata_tags_4[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_padata_4,
	1,	/* Single element */
	&asn_SPC_padata_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_KDC_REQ_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct KDC_REQ, pvno),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"pvno"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct KDC_REQ, msg_type),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"msg-type"
		},
	{ ATF_POINTER, 1, offsetof(struct KDC_REQ, padata),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		0,
		&asn_DEF_padata_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"padata"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct KDC_REQ, req_body),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_KDC_REQ_BODY,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"req-body"
		},
};
static const ber_tlv_tag_t asn_DEF_KDC_REQ_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_KDC_REQ_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 0, 0, 0 }, /* pvno */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 1, 0, 0 }, /* msg-type */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 2, 0, 0 }, /* padata */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 3, 0, 0 } /* req-body */
};
static asn_SEQUENCE_specifics_t asn_SPC_KDC_REQ_specs_1 = {
	sizeof(struct KDC_REQ),
	offsetof(struct KDC_REQ, _asn_ctx),
	asn_MAP_KDC_REQ_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_KDC_REQ = {
	"KDC-REQ",
	"KDC-REQ",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_KDC_REQ_tags_1,
	sizeof(asn_DEF_KDC_REQ_tags_1)
		/sizeof(asn_DEF_KDC_REQ_tags_1[0]), /* 1 */
	asn_DEF_KDC_REQ_tags_1,	/* Same as above */
	sizeof(asn_DEF_KDC_REQ_tags_1)
		/sizeof(asn_DEF_KDC_REQ_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_KDC_REQ_1,
	4,	/* Elements count */
	&asn_SPC_KDC_REQ_specs_1	/* Additional specs */
};

