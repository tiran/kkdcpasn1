/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "KKDCP"
 * 	found in "kkdcp.asn1"
 */

#ifndef	_HostAddresses_H_
#define	_HostAddresses_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct HostAddress;

/* HostAddresses */
typedef struct HostAddresses {
	A_SEQUENCE_OF(struct HostAddress) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HostAddresses_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HostAddresses;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "HostAddress.h"

#endif	/* _HostAddresses_H_ */
#include <asn_internal.h>
