#include <stdio.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

static STACK_OF(CONF_VALUE) *i2v_MIDDLEBOX_INFO(X509V3_EXT_METHOD *method,
				MIDDLEBOX_INFO *minfo, STACK_OF(CONF_VALUE) *ret);
static MIDDLEBOX_INFO *v2i_MIDDLEBOX_INFO(X509V3_EXT_METHOD *method,
				 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);

const X509V3_EXT_METHOD v3_mbi =
{ NID_middleboxInfo, X509V3_EXT_MULTILINE, ASN1_ITEM_ref(MIDDLEBOX_INFO),
0,0,0,0,
0,0,
(X509V3_EXT_I2V)i2v_MIDDLEBOX_INFO,
(X509V3_EXT_V2I)v2i_MIDDLEBOX_INFO,
0,0,
NULL};

static STACK_OF(CONF_VALUE) *i2v_MIDDLEBOX_INFO(X509V3_EXT_METHOD *method,
				MIDDLEBOX_INFO *minfo, STACK_OF(CONF_VALUE) *ret)
{
	MIDDLEBOX_DESCRIPTION *desc;
	int i,nlen;
	char objtmp[80], *ntmp;
	CONF_VALUE *vtmp;
	for(i = 0; i < sk_MIDDLEBOX_DESCRIPTION_num(minfo); i++) {
		desc = sk_MIDDLEBOX_DESCRIPTION_value(minfo, i);
		ret = i2v_GENERAL_NAME(method, desc->middlebox_info_value, ret);
		if(!ret) break;
		vtmp = sk_CONF_VALUE_value(ret, i);
		i2t_ASN1_OBJECT(objtmp, sizeof objtmp, desc->middlebox_info_type);
		nlen = strlen(objtmp) + strlen(vtmp->name) + 5;
		ntmp = OPENSSL_malloc(nlen);
		if(!ntmp) {
			X509V3err(X509V3_F_I2V_MIDDLEBOX_INFO, ERR_R_MALLOC_FAILURE);
			return NULL;
		}
		BUF_strlcpy(ntmp, objtmp, nlen);
		BUF_strlcat(ntmp, " - ", nlen);
		BUF_strlcat(ntmp, vtmp->name, nlen);
		OPENSSL_free(vtmp->name);
		vtmp->name = ntmp;
		
	}
	if(!ret) return sk_CONF_VALUE_new_null();
	return ret;
}

static MIDDLEBOX_INFO *v2i_MIDDLEBOX_INFO(X509V3_EXT_METHOD *method,
				 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
	MIDDLEBOX_INFO *minfo = NULL;
	CONF_VALUE *cnf, ctmp;
	MIDDLEBOX_DESCRIPTION *desc;
	int i, objlen;
	char *objtmp, *ptmp;
	if(!(minfo = sk_MIDDLEBOX_DESCRIPTION_new_null())) {
		X509V3err(X509V3_F_V2I_MIDDLEBOX_INFO,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	for(i = 0; i < sk_CONF_VALUE_num(nval); i++) {
		cnf = sk_CONF_VALUE_value(nval, i);
		if(!(desc = MIDDLEBOX_DESCRIPTION_new())
			|| !sk_MIDDLEBOX_DESCRIPTION_push(minfo, desc)) {
			X509V3err(X509V3_F_V2I_MIDDLEBOX_INFO,ERR_R_MALLOC_FAILURE);
			goto err;
		}
		ptmp = strchr(cnf->name, ';');
		if(!ptmp) {
			X509V3err(X509V3_F_V2I_MIDDLEBOX_INFO,X509V3_R_INVALID_SYNTAX);
			goto err;
		}
		objlen = ptmp - cnf->name;
		ctmp.name = ptmp + 1;
		ctmp.value = cnf->value;
		if(!v2i_GENERAL_NAME_ex(desc->middlebox_info_value, method, ctx, &ctmp, 0))
								 goto err; 
		if(!(objtmp = OPENSSL_malloc(objlen + 1))) {
			X509V3err(X509V3_F_V2I_MIDDLEBOX_INFO,ERR_R_MALLOC_FAILURE);
			goto err;
		}
		strncpy(objtmp, cnf->name, objlen);
		objtmp[objlen] = 0;
		desc->middlebox_info_type = OBJ_txt2obj(objtmp, 0);
		if(!desc->middlebox_info_type) {
			X509V3err(X509V3_F_V2I_MIDDLEBOX_INFO,X509V3_R_BAD_OBJECT);
			ERR_add_error_data(2, "value=", objtmp);
			OPENSSL_free(objtmp);
			goto err;
		}
		OPENSSL_free(objtmp);

	}
	return minfo;
	err:
	sk_MIDDLEBOX_DESCRIPTION_pop_free(minfo, MIDDLEBOX_DESCRIPTION_free);
	return NULL;
}

int i2a_MIDDLEBOX_DESCRIPTION(BIO *bp, MIDDLEBOX_DESCRIPTION* a)
{
	i2a_ASN1_OBJECT(bp, a->middlebox_info_type);
#ifdef UNDEF
	i2a_GENERAL_NAME(bp, a->middlebox_info_value);
#endif
	return 2;
}
