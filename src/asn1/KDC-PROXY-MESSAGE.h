/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "KKDCP"
 * 	found in "kkdcp.asn1"
 */

#ifndef	_KDC_PROXY_MESSAGE_H_
#define	_KDC_PROXY_MESSAGE_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include "Realm.h"
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* KDC-PROXY-MESSAGE */
typedef struct KDC_PROXY_MESSAGE {
	OCTET_STRING_t	 kerb_message;
	Realm_t	*target_domain	/* OPTIONAL */;
	long	*dclocator_hint	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} KDC_PROXY_MESSAGE_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_KDC_PROXY_MESSAGE;

#ifdef __cplusplus
}
#endif

#endif	/* _KDC_PROXY_MESSAGE_H_ */
#include <asn_internal.h>
