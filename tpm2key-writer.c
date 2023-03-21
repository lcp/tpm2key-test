/* gcc -ltasn1 tpm2key_asn1_tab.o tpm2key-writer.c -o tpm2key-writer */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libtasn1.h>

extern asn1_static_node tpm2key_asn1_tab[];

const char *sealed_key_oid = "2.23.133.10.1.5";
const uint32_t test_parent = 0x40000001;
const char test_pubkey[] = {0x00, 0x00, 0x00, 0x01};
const char test_privkey[] = {0x11, 0x11, 0x11, 0x22, 0x22, 0x22};
const char *outfile = "test.der";

#define UINT32_CHAR_MAX 11

int
gen_der_from_asn1 (void **buffer, int *buffer_size, const uint32_t parent,
		   const void *pubkey, const int pubkey_size, const void *privkey,
		   const int privkey_size)
{
	asn1_node asn1_def = NULL;
	asn1_node tpm2key = NULL;
	uint32_t tmp;
	char parent_str[UINT32_CHAR_MAX];
	char *pubkey_str = NULL;
	char *privkey_str = NULL;
	void *der_buff = NULL;
	int der_buff_size = 0;
	int ret;

	ret = asn1_array2tree (tpm2key_asn1_tab, &asn1_def, NULL);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to convert the array to tree\n");
		return -1;
	}

	ret = asn1_create_element (asn1_def, "TPM2KEY.TPMKey" , &tpm2key);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to create the element\n");
		return -1;
	}

	/* Set 'type' to "sealed key" */
	ret = asn1_write_value (tpm2key, "type", sealed_key_oid, 1);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to write type\n");
		goto error;
	}

	/* Set 'emptyAuth' to TRUE */
	ret = asn1_write_value (tpm2key, "emptyAuth", "TRUE", 1);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to write type\n");
		goto error;
	}

	/* Remove 'policy' */
	ret = asn1_write_value (tpm2key, "policy", NULL, 0);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to write policy\n");
		goto error;
	}

	/* Remove 'secret' */
	ret = asn1_write_value (tpm2key, "secret", NULL, 0);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to write secret\n");
		goto error;
	}

	/* Remove 'authPolicy' */
	ret = asn1_write_value (tpm2key, "authPolicy", NULL, 0);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to write authPolicy\n");
		goto error;
	}

	/* Specify the parent handle */
	snprintf (parent_str, UINT32_CHAR_MAX, "%u", parent);
	tmp = __builtin_bswap32 (parent);
	ret = asn1_write_value (tpm2key, "parent", &tmp, sizeof(tmp));
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to write parent\n");
		goto error;
	}

	/* Set the pubkey */
	ret = asn1_write_value (tpm2key, "pubkey", pubkey, pubkey_size);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to write pubkey\n");
		goto error;
	}

	/* Set the privkey */
	ret = asn1_write_value (tpm2key, "privkey", privkey, privkey_size);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to write privkey\n");
		goto error;
	}

	/* Create the DER binary */
	der_buff_size = 0;
	ret = asn1_der_coding (tpm2key, "", NULL, &der_buff_size, NULL);
	if (ret != ASN1_MEM_ERROR) {
		printf ("Failed to get DER size\n");
		goto error;
	}

	der_buff = malloc (der_buff_size);
	if (der_buff == NULL) {
		printf ("Failed to allocate DER buffer\n");
		ret = ASN1_MEM_ERROR;
		goto error;
	}

	ret = asn1_der_coding (tpm2key, "", der_buff, &der_buff_size, NULL);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to write DER buffer\n");
		free (der_buff);
		goto error;
	}

	*buffer = der_buff;
	*buffer_size = der_buff_size;

	ret = 0;

error:
	if (tpm2key)
		asn1_delete_structure (&tpm2key);

	return ret;
}

int
main ()
{
	FILE *der_file;
	void *buf;
	int buf_size;
	size_t write_n;
	int ret;

	der_file = fopen (outfile, "w");
	if (der_file == NULL) {
		printf ("Failed to open %s\n", outfile);
		return -1;
	}

	ret = gen_der_from_asn1 (&buf, &buf_size, test_parent, test_pubkey,
				 sizeof(test_pubkey), test_privkey,
				 sizeof(test_privkey));
	if (ret != 0) {
		printf ("Failed to generate test tpm2key der\n");
		goto error;
	}

	write_n = fwrite (buf, 1, buf_size, der_file);
	if (write_n != buf_size) {
		printf ("Failed to write %s\n", outfile);
		ret = -1;
		goto error;
	}

error:
	fclose (der_file);
	
	return ret;
}
