/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "KKDCP"
 * 	found in "kkdcp.asn1"
 */

#ifndef	_Realm_H_
#define	_Realm_H_


#include <asn_application.h>

/* Including external dependencies */
#include <GeneralString.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Realm */
typedef GeneralString_t	 Realm_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Realm;
asn_struct_free_f Realm_free;
asn_struct_print_f Realm_print;
asn_constr_check_f Realm_constraint;
ber_type_decoder_f Realm_decode_ber;
der_type_encoder_f Realm_encode_der;
xer_type_decoder_f Realm_decode_xer;
xer_type_encoder_f Realm_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _Realm_H_ */
#include <asn_internal.h>
