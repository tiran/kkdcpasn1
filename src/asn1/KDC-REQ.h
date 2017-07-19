/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "KKDCP"
 * 	found in "kkdcp.asn1"
 */

#ifndef	_KDC_REQ_H_
#define	_KDC_REQ_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include "KDC-REQ-BODY.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PA_DATA;

/* KDC-REQ */
typedef struct KDC_REQ {
	long	 pvno;
	long	 msg_type;
	struct padata {
		A_SEQUENCE_OF(struct PA_DATA) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *padata;
	KDC_REQ_BODY_t	 req_body;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} KDC_REQ_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_KDC_REQ;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PA-DATA.h"

#endif	/* _KDC_REQ_H_ */
#include <asn_internal.h>
