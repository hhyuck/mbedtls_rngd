/*
 *  Certificate request generation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"
/* md.h is included this early since MD_CAN_XXX macros are defined there. */
#include "mbedtls/md.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
//#include "test/helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SET_OID(x, oid) \
    do { x.len = MBEDTLS_OID_SIZE(oid); x.p = (unsigned char *) oid; } while (0)

#define RNGD_CERT_APP_DEFAULT_FILENAME				"RNGD.key"
#define RNGD_CERT_APP_DEFAULT_PASSWORD				NULL
#define RNGD_CERT_APP_DEFAULT_CSR_OUTPUT_FILENAME	"RNGD.req"
#define RNGD_CERT_APP_DEFAULT_CRT_OUTPUT_FILENAME	"RNGD.crt"
#define RNGD_CERT_APP_DEFAULT_SUBJECT_NAME			"CN=RNGD,O=FuriosaAI,C=KR"
#define RNGD_CERT_APP_DEFAULT_MD_ALG				MBEDTLS_MD_SHA384

#define RNGD_CERT_APP_DEFAULT_ISSUER_NAME			"CN=RNGD INTER CA,O=FuriosaAI,C=KR"
#define RNGD_CERT_APP_DEFAULT_ISSUER_KEY			"RNGD_INTER_CA.key"
#define RNGD_CERT_APP_DEFAULT_ISSUER_PWD			""
#define RNGD_CERT_APP_DEFAULT_NOT_BEFORE			"20250101000000"
#define RNGD_CERT_APP_DEFAULT_NOT_AFTER				"20351231235959"
#define RNGD_CERT_APP_DEFAULT_SERIAL				"1"

static int write_certificate_request(mbedtls_x509write_csr *req, const char *output_file,
		int (*f_rng)(void *, unsigned char *, size_t),
		void *p_rng) {
	int ret;
	FILE *f;
	unsigned char output_buf[4096];
	size_t len = 0;

	memset(output_buf, 0, 4096);
	if ((ret = mbedtls_x509write_csr_pem(req, output_buf, 4096, f_rng, p_rng)) < 0) {
		return ret;
	}

	len = strlen((char *) output_buf);

	if ((f = fopen(output_file, "w")) == NULL) {
		return -1;
	}

	if (fwrite(output_buf, 1, len, f) != len) {
		fclose(f);
		return -1;
	}

	fclose(f);

	return 0;
}

static int write_certificate(mbedtls_x509write_cert *crt, const char *output_file,
		int (*f_rng)(void *, unsigned char *, size_t),
		void *p_rng) {
	int ret;
	FILE *f;
	unsigned char output_buf[4096];
	unsigned char *output_start;
	size_t len = 0;

	memset(output_buf, 0, 4096);
	/*if (opt.format == FORMAT_DER) {
	  ret = mbedtls_x509write_crt_der(crt, output_buf, 4096,
	  f_rng, p_rng);
	  if (ret < 0) {
	  return ret;
	  }

	  len = ret;
	  output_start = output_buf + 4096 - len;
	  } else {*/
	ret = mbedtls_x509write_crt_pem(crt, output_buf, 4096,
			f_rng, p_rng);
	if (ret < 0) {
		return ret;
	}

	len = strlen((char *) output_buf);
	output_start = output_buf;
	//}

	if ((f = fopen(output_file, "w")) == NULL) {
		return -1;
	}

	if (fwrite(output_start, 1, len, f) != len) {
		fclose(f);
		return -1;
	}

	fclose(f);

	return 0;
}

static int parse_serial_decimal_format(unsigned char *obuf, size_t obufmax,
		const char *ibuf, size_t *len) {
	unsigned long long int dec;
	unsigned int remaining_bytes = sizeof(dec);
	unsigned char *p = obuf;
	unsigned char val;
	char *end_ptr = NULL;

	errno = 0;
	dec = strtoull(ibuf, &end_ptr, 10);

	if ((errno != 0) || (end_ptr == ibuf)) {
		return -1;
	}

	*len = 0;

	while (remaining_bytes > 0) {
		if (obufmax < (*len + 1)) {
			return -1;
		}

		val = (dec >> ((remaining_bytes - 1) * 8)) & 0xFF;

		/* Skip leading zeros */
		if ((val != 0) || (*len != 0)) {
			*p = val;
			(*len)++;
			p++;
		}

		remaining_bytes--;
	}

	return 0;
}

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
	int ret = 1;
	int exit_code = MBEDTLS_EXIT_FAILURE;
	mbedtls_pk_context key;
	char buf[1024];
	char subject_name[256];
	mbedtls_x509write_csr req;
	mbedtls_x509_csr csr;
	mbedtls_x509write_cert crt;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_pk_context loaded_issuer_key;
	mbedtls_pk_context *subject_key, *issuer_key = &loaded_issuer_key;
	const char *pers = "Furiosa RNGD CERT APP";
	unsigned char serial[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN];
	size_t serial_len;
	mbedtls_asn1_sequence *ext_key_usage, *ext_key_usage_tmp;
	mbedtls_asn1_sequence **tail = &ext_key_usage;

	mbedtls_x509write_csr_init(&req);
	mbedtls_pk_init(&key);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	memset(buf, 0, sizeof(buf));
	mbedtls_entropy_init(&entropy);

	mbedtls_x509write_crt_init(&crt);
	mbedtls_pk_init(&loaded_issuer_key);
	memset(serial, 0, sizeof(serial));

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                        (int) status);
        goto exit;
    }

	ret = parse_serial_decimal_format(serial, sizeof(serial),
			RNGD_CERT_APP_DEFAULT_SERIAL, &serial_len);

	if (ret != 0) {
		mbedtls_printf(" failed\n  !  Unable to parse serial\n");
		goto exit;
	}

	/* Set the MD algorithm to use for the signature in the CSR */
	mbedtls_x509write_csr_set_md_alg(&req, RNGD_CERT_APP_DEFAULT_MD_ALG);

	/*
	 * 0. Seed the PRNG
	 */
	mbedtls_printf("  . Seeding the random number generator...");
	fflush(stdout);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
					(const unsigned char *) pers,
					strlen(pers))) != 0) {
		mbedtls_printf(" failed\n  !  mbedtls_ctr_drbg_seed returned %d", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * 1.0. Check the subject name for validity
	 */
	mbedtls_printf("  . Checking subject name...");
	fflush(stdout);

	if ((ret = mbedtls_x509write_csr_set_subject_name(&req, RNGD_CERT_APP_DEFAULT_SUBJECT_NAME)) != 0) {
		mbedtls_printf(" failed\n  !  mbedtls_x509write_csr_set_subject_name returned %d", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * 1.1. Load the key
	 */
	mbedtls_printf("  . Loading the private key ...");
	fflush(stdout);

	ret = mbedtls_pk_parse_keyfile(&key, RNGD_CERT_APP_DEFAULT_FILENAME, RNGD_CERT_APP_DEFAULT_PASSWORD,
			mbedtls_ctr_drbg_random, &ctr_drbg);

	if (ret != 0) {
		mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile returned %d", ret);
		goto exit;
	}

	mbedtls_x509write_csr_set_key(&req, &key);

	mbedtls_printf(" ok\n");

	/*
	 * 1.2. Writing the request
	 */
	mbedtls_printf("  . Writing the certificate request ...");
	fflush(stdout);

	if ((ret = write_certificate_request(&req, RNGD_CERT_APP_DEFAULT_CSR_OUTPUT_FILENAME,
					mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
		mbedtls_printf(" failed\n  !  write_certificate_request %d", ret);
		//goto exit;

		return ret;
	}

	/*
	 * 2.1. Load the CSR
	 */
	mbedtls_printf("  . Loading the certificate request ...");
	fflush(stdout);

	if ((ret = mbedtls_x509_csr_parse_file(&csr, RNGD_CERT_APP_DEFAULT_CSR_OUTPUT_FILENAME)) != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  mbedtls_x509_csr_parse_file "
				"returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
		goto exit;
	}

	ret = mbedtls_x509_dn_gets(subject_name, sizeof(subject_name),
			&csr.subject);
	if (ret < 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  mbedtls_x509_dn_gets "
				"returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
		goto exit;
	}

	subject_key = &csr.pk;

	mbedtls_printf(" ok\n");

	/*
	 * 2.2. Load the keys
	 */
	mbedtls_printf("  . Loading the issuer key ...");
	fflush(stdout);

	ret = mbedtls_pk_parse_keyfile(&loaded_issuer_key, RNGD_CERT_APP_DEFAULT_ISSUER_KEY,
			RNGD_CERT_APP_DEFAULT_ISSUER_PWD, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile "
				"returned -x%02x - %s\n\n", (unsigned int) -ret, buf);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	mbedtls_x509write_crt_set_subject_key(&crt, subject_key);
	mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);

	/*
	 * 2.3. Check the names for validity
	 */
	if ((ret = mbedtls_x509write_crt_set_subject_name(&crt, RNGD_CERT_APP_DEFAULT_SUBJECT_NAME)) != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_subject_name "
				"returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
		goto exit;
	}

	if ((ret = mbedtls_x509write_crt_set_issuer_name(&crt, RNGD_CERT_APP_DEFAULT_ISSUER_NAME)) != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_issuer_name "
				"returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
		goto exit;
	}

	mbedtls_printf("  . Setting certificate values ...");
	fflush(stdout);

	mbedtls_x509write_crt_set_version(&crt, 2); //V3
	mbedtls_x509write_crt_set_md_alg(&crt, RNGD_CERT_APP_DEFAULT_MD_ALG);

	ret = mbedtls_x509write_crt_set_serial_raw(&crt, serial, serial_len);
	if (ret != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_serial_raw "
				"returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
		goto exit;
	}

	ret = mbedtls_x509write_crt_set_validity(&crt, RNGD_CERT_APP_DEFAULT_NOT_BEFORE, 
		RNGD_CERT_APP_DEFAULT_NOT_AFTER);

	if (ret != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_validity "
				"returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	mbedtls_printf("  . Adding the Basic Constraints extension ...");
	fflush(stdout);

	ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
	if (ret != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  x509write_crt_set_basic_constraints "
				"returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	mbedtls_printf("  . Adding the Subject Key Identifier ...");
	fflush(stdout);

	ret = mbedtls_x509write_crt_set_subject_key_identifier(&crt);
	if (ret != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_subject"
				"_key_identifier returned -0x%04x - %s\n\n",
				(unsigned int) -ret, buf);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	mbedtls_printf("  . Adding the Authority Key Identifier ...");
	fflush(stdout);

	ret = mbedtls_x509write_crt_set_authority_key_identifier(&crt);
	if (ret != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_authority_"
				"key_identifier returned -0x%04x - %s\n\n",
				(unsigned int) -ret, buf);
		goto exit;
	}

	mbedtls_printf(" ok\n");


	mbedtls_printf("  . Adding the Key Usage extension ...");
	fflush(stdout);

	ret = mbedtls_x509write_crt_set_key_usage(&crt, 
		MBEDTLS_X509_KU_DIGITAL_SIGNATURE|MBEDTLS_X509_KU_NON_REPUDIATION|MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
	if (ret != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_key_usage "
				"returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	mbedtls_printf("  . Adding the Extended Key Usage extension ...");
	fflush(stdout);

	ext_key_usage_tmp = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
	ext_key_usage_tmp->buf.tag = MBEDTLS_ASN1_OID;
	SET_OID(ext_key_usage_tmp->buf, MBEDTLS_OID_SERVER_AUTH);
	*tail = ext_key_usage_tmp;
	tail = &ext_key_usage_tmp->next;

	ext_key_usage_tmp = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
	ext_key_usage_tmp->buf.tag = MBEDTLS_ASN1_OID;
	SET_OID(ext_key_usage_tmp->buf, MBEDTLS_OID_CLIENT_AUTH);
	*tail = ext_key_usage_tmp;
	tail = &ext_key_usage_tmp->next;

	ext_key_usage_tmp = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
	ext_key_usage_tmp->buf.tag = MBEDTLS_ASN1_OID;
	SET_OID(ext_key_usage_tmp->buf, MBEDTLS_OID_OCSP_SIGNING);
	*tail = ext_key_usage_tmp;
	tail = &ext_key_usage_tmp->next;

	ret = mbedtls_x509write_crt_set_ext_key_usage(&crt, ext_key_usage);

	if (ret != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(
				" failed\n  !  mbedtls_x509write_crt_set_ext_key_usage returned -0x%02x - %s\n\n",
				(unsigned int) -ret,
				buf);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * 2.10. Writing the certificate
	 */
	mbedtls_printf("  . Writing the certificate...");
	fflush(stdout);

	if ((ret = write_certificate(&crt, RNGD_CERT_APP_DEFAULT_CRT_OUTPUT_FILENAME,
					mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" failed\n  !  write_certificate -0x%04x - %s\n\n",
				(unsigned int) -ret, buf);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

	if (exit_code != MBEDTLS_EXIT_SUCCESS) {
#ifdef MBEDTLS_ERROR_C
		mbedtls_strerror(ret, buf, sizeof(buf));
		mbedtls_printf(" - %s\n", buf);
#else
		mbedtls_printf("\n");
#endif
	}

	mbedtls_x509write_csr_free(&req);
	mbedtls_x509_csr_free(&csr);
	mbedtls_x509write_crt_free(&crt);
	mbedtls_pk_free(&loaded_issuer_key);
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
	mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

	mbedtls_exit(exit_code);
}
