/* gcc -ltasn1 tpm2key_asn1_tab.o tpm2key-parser.c -o tpm2key-parser */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libtasn1.h>

#define MAX_OID_LEN 32

extern asn1_static_node tpm2key_asn1_tab[];
const char *sealed_key_oid = "2.23.133.10.1.5";

static char asn1_error[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

asn1_node _tpm2key_asn1 = NULL;

asn1_node parsed_tpm2key = NULL;

void
dump_hex (uint8_t *data, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		printf ("%02x ", *(data + i));
	}

	printf ("\n");
}

int
asn1_init ()
{
	int ret;

	ret = asn1_array2tree (tpm2key_asn1_tab, &_tpm2key_asn1, NULL);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to get the definitions\n");
		return -1;
	}

	return 0;
}

static int
asn1_allocate_and_read (asn1_node node, const char *name, void **content, int *content_size)
{
	uint8_t *tmpstr = NULL;
	int tmpstr_size = 0;
	int ret;

	if (content == NULL)
		return ASN1_MEM_ERROR;

	ret = asn1_read_value (node, name, NULL, &tmpstr_size);
	if (ret != ASN1_MEM_ERROR) {
		return ret;
	}

	tmpstr = malloc (tmpstr_size);
	if (tmpstr == NULL) {
		return ASN1_MEM_ERROR;
	}

	ret = asn1_read_value (node, name, tmpstr, &tmpstr_size);
	if (ret != ASN1_SUCCESS) {
		return ret;
	}

	*content = tmpstr;
	*content_size = tmpstr_size;

	return ASN1_SUCCESS;
}

static int
asn1_read_uint32 (asn1_node node, const char *name, uint32_t *out)
{
	uint32_t tmp = 0;
	void *ptr;
	void *data = NULL;
	int data_size;
	int ret;

	ret = asn1_allocate_and_read (node, name, &data, &data_size);
	if (ret != ASN1_SUCCESS) {
		return ret;
	}

	if (data_size > 4) {
		ret = ASN1_MEM_ERROR;
		goto error;
	}

	/* convert the big-endian integer to host uint32 */
	ptr = (void *)&tmp + (4 - data_size);
	memcpy (ptr, data, data_size);
	/* FIXME be_to_cpu32 */
	tmp = __builtin_bswap32 (tmp);

	*out = tmp;
error:
	if (data)
		free (data);
	return ret;
}

int
grub_tpm2key_start_parsing (void *data, int size)
{
	asn1_node tpm2key;
	void *type_oid = NULL;
	int type_oid_size = 0;
	void *empty_auth = NULL;
	int empty_auth_size = 0;
	int tmp_size = 0;
	int ret;

	/*
	  TPMKey ::= SEQUENCE {
	      type        OBJECT IDENTIFIER,
	      emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
	      policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
	      secret      [2] EXPLICIT OCTET STRING OPTIONAL,
	      authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
	      parent      INTEGER,
	      pubkey      OCTET STRING,
	      privkey     OCTET STRING
	  }
	*/
	ret = asn1_create_element (_tpm2key_asn1, "TPM2KEY.TPMKey", &tpm2key);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to create element\n");
		return -1;
	}

	ret = asn1_der_decoding (&tpm2key, data, size, asn1_error);
	if (ret != ASN1_SUCCESS) {
		printf ("DER decoding error: %s\n", asn1_error);
		ret = -1;
		goto error;
	}

	/* Check if 'type' is Sealed Key or not */
	ret = asn1_allocate_and_read (tpm2key, "type", &type_oid, &type_oid_size);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to read type: %d\n", ret);
		ret = -1;
		goto error;
	}

	if (memcmp (sealed_key_oid, type_oid, type_oid_size) != 0) {
		printf ("NOT a sealed key\n");
		ret = -1;
		goto error;
	}

	/* 'emptyAuth' must be 'TRUE' since we don't support password authorization */
	ret = asn1_allocate_and_read (tpm2key, "emptyAuth", &empty_auth, &empty_auth_size);
	if (ret != ASN1_SUCCESS || strncmp ("TRUE", empty_auth, empty_auth_size) != 0) {
		ret = -1;
		goto error;
	}

	/* 'secret' should not be in a sealed key */
	ret = asn1_read_value (tpm2key, "secret", NULL, &tmp_size);
	if (ret != ASN1_ELEMENT_NOT_FOUND) {
		ret = -1;
		goto error;
	}

	parsed_tpm2key = tpm2key;

	ret = 0;
error:
	if (type_oid)
		free (type_oid);

	return ret;
}

/* TODO
 * grub_tpm2key_get_authPolicy
 */

int
grub_tpm2key_get_parent (uint32_t *parent)
{
	int ret;

	if (parent == NULL)
		return -1;

	if (parsed_tpm2key == NULL)
		return -1;

	/* parent  INTEGER */
	ret = asn1_read_uint32 (parsed_tpm2key, "parent", parent);
	if (ret != ASN1_SUCCESS) {
		return -1;
	}

	return 0;
}

static int
tpm2key_get_octstring (const char *name, void **data, int *size)
{
	int ret;

	if (name == NULL || data == NULL || size == NULL)
		return -1;

	if (parsed_tpm2key == NULL)
		return -1;

	ret = asn1_allocate_and_read (parsed_tpm2key, name, data, size);
	if (ret != ASN1_SUCCESS)
		return -1;

	return 0;
}

int
grub_tpm2key_get_pubkey (void **data, int *size)
{
	return tpm2key_get_octstring ("pubkey", data, size);
}

int
grub_tpm2key_get_privkey (void **data, int *size)
{
	return tpm2key_get_octstring ("privkey", data, size);
}

void
grub_tpm2key_end_parsing ()
{
	if (parsed_tpm2key)
		asn1_delete_structure (&parsed_tpm2key);
	parsed_tpm2key = NULL;
}

void
print_authpolicy ()
{
	asn1_node tpm2key;
	int policy_n;
	int ret;

	tpm2key = parsed_tpm2key;

	/* authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL */
	ret = asn1_number_of_elements (tpm2key, "authPolicy", &policy_n);
	if (ret == ASN1_SUCCESS) {
		char seq_name[40];
		int sub_pol_n;

		printf ("%d authPolicy found\n", policy_n);

		for (int i = 1; i <= policy_n; i++) {
			char *ap_name = NULL;
			int ap_name_len;
			char code_name[40];
			char policy_name[40];
			uint32_t command_code;

			snprintf (seq_name, sizeof(seq_name), "authPolicy.?%d.Name", i);

			ret = asn1_allocate_and_read (tpm2key, seq_name, (void **)&ap_name, &ap_name_len);
			if (ret == ASN1_SUCCESS && ap_name) {
				printf ("  %s: %s\n", seq_name, ap_name);
				free (ap_name);
			}

			snprintf (seq_name, sizeof(seq_name), "authPolicy.?%d.Policy", i);
			ret = asn1_number_of_elements (tpm2key, seq_name, &sub_pol_n);
			if (ret != ASN1_SUCCESS) {
				printf ("Failed to fetch the size of authPolicy.?%d.Policy\n", i);
				goto error;
			}

			printf ("  %d authPolicy.Policy found\n", sub_pol_n);

			for (int j = 1; j <= sub_pol_n; j++) {
				snprintf (code_name, sizeof(code_name),
					 "authPolicy.?%d.Policy.?%d.CommandCode", i, j);
				ret = asn1_read_uint32 (tpm2key, code_name, &command_code);
				
				printf ("    %s: 0x%04x\n", code_name, command_code);
			}
		}
	}
error:
	return;
}

int
process_content (uint8_t *content, int size)
{
	asn1_node tpm2key;
	void *type_oid = NULL;
	int type_oid_size = 0;
	void *empty_auth_str = NULL;
	int empty_auth_size = 0;
	uint8_t empty_auth = 0;
	int policy_n;
	void *policy_data = NULL;
	int policy_data_size = 0;
	uint32_t parent = 0;
	void *pubkey_data = NULL;
	int pubkey_data_size = 0;
	void *privkey_data = NULL;
	int privkey_data_size = 0;
	int tmp_size = 0;
	int ret;

	/*
	 TPMKey ::= SEQUENCE {
	     type        OBJECT IDENTIFIER,
	     emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
	     policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
	     secret      [2] EXPLICIT OCTET STRING OPTIONAL,
	     authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
	     parent      INTEGER,
	     pubkey      OCTET STRING,
	     privkey     OCTET STRING
	 }
	*/

	ret = asn1_create_element (_tpm2key_asn1, "TPM2KEY.TPMKey", &tpm2key);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to create element\n");
		return ret;
	}

	ret = asn1_der_decoding (&tpm2key, content, size, asn1_error);
	if (ret != ASN1_SUCCESS) {
		printf ("DER decoding error: %s\n", asn1_error);
		goto error;
	}

	/* type  OBJECT IDENTIFIER */
	ret = asn1_allocate_and_read (tpm2key, "type", &type_oid, &type_oid_size);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to read type: %d\n", ret);
		goto error;
	}

	if (memcmp (sealed_key_oid, type_oid, type_oid_size) != 0) {
		printf ("NOT a sealed key\n");
		ret = -1;
		goto error;
	}

	printf ("type: %s\n", sealed_key_oid);

	/* emptyAuth  [0] EXPLICIT BOOLEAN OPTIONAL */
	ret = asn1_allocate_and_read (tpm2key, "emptyAuth", &empty_auth_str, &empty_auth_size);
	if (ret != ASN1_SUCCESS && ret != ASN1_ELEMENT_NOT_FOUND) {
		printf ("Failed to read emptyAuth: %d\n", ret);
		goto error;
	}

	if (ret == ASN1_ELEMENT_NOT_FOUND) {
		empty_auth = 0;
	} else if (strcmp ("TRUE", empty_auth_str) == 0) {
		empty_auth = 1;
	} else if (strcmp ("FALSE", empty_auth_str) == 0) {
		empty_auth = 0;
	} else {
		printf ("Invalid emptyAuth\n");
		goto error;
	}

	printf ("emptyAuth: %s\n", empty_auth ? "TRUE" : "FALSE");

	if (empty_auth == 0) {
		printf ("Authorization is not supported.");
		goto error;
	}

	/* policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL */
	ret = asn1_number_of_elements (tpm2key, "policy", &policy_n);
	if (ret == ASN1_SUCCESS) {
		char code_name[40];
		char policy_name[40];
		uint32_t command_code;

		/* limit the number of policies >0 && <= 100 */
		printf ("%d policy found\n", policy_n);

		for (int i = 1; i <= policy_n; i++) {
			snprintf (code_name, sizeof(code_name), "policy.?%d.CommandCode", i);
			ret = asn1_read_uint32 (tpm2key, code_name, &command_code);
			if (ret != ASN1_SUCCESS) {
				printf ("Failed to read CommandCode\n");
				goto error;
			}
			printf ("%s: 0x%04x\n", code_name, command_code);

			snprintf (policy_name, sizeof(policy_name), "policy.?%d.CommandPolicy", i);
			ret = asn1_allocate_and_read (tpm2key, policy_name,
						      &policy_data, &policy_data_size);
			if (ret != ASN1_SUCCESS) {
				printf ("Failed to read CommandPolicy\n");
			}
			printf ("%s_size: %d\n", policy_name, policy_data_size);
			dump_hex (policy_data, policy_data_size);
		}
	}

	/* secret      [2] EXPLICIT OCTET STRING OPTIONAL */
	ret = asn1_read_value (tpm2key, "secret", NULL, &tmp_size);
	if (ret != ASN1_ELEMENT_NOT_FOUND) {
		printf ("'secret' should not be in a sealed key\n");
		goto error;
	}

	/* authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL */
	ret = asn1_number_of_elements (tpm2key, "authPolicy", &policy_n);
	if (ret == ASN1_SUCCESS) {
		char seq_name[40];
		int sub_pol_n;

		printf ("%d authPolicy found\n", policy_n);

		for (int i = 1; i <= policy_n; i++) {
			char code_name[40];
			char policy_name[40];
			uint32_t command_code;

			snprintf (seq_name, sizeof(seq_name), "authPolicy.?%d.Policy", i);
			ret = asn1_number_of_elements (tpm2key, seq_name, &sub_pol_n);
			if (ret != ASN1_SUCCESS) {
				printf ("Failed to fetch the size of authPolicy.?%d.Policy\n", i);
				goto error;
			}

			printf ("%d authPolicy.Policy found\n", sub_pol_n);

			for (int j = 1; j <= sub_pol_n; j++) {
				snprintf (code_name, sizeof(code_name),
					 "authPolicy.?%d.Policy.?%d.CommandCode", i, j);
				ret = asn1_read_uint32 (tpm2key, code_name, &command_code);
				
				printf ("%s: 0x%04x\n", code_name, command_code);
			}
		}
	}

	/* parent  INTEGER */
	ret = asn1_read_uint32 (tpm2key, "parent", &parent);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to read parent\n");
		goto error;
	}

	printf ("parent: 0x%x\n", parent);

	/* pubkey  OCTET STRING */
	ret = asn1_allocate_and_read (tpm2key, "pubkey", &pubkey_data, &pubkey_data_size);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to read pubkey\n");
		goto error;
	}
	printf ("pubkey_data_size: %d\n", pubkey_data_size);
	dump_hex (pubkey_data, pubkey_data_size);

	/* privkey  OCTET STRING */
	ret = asn1_allocate_and_read (tpm2key, "privkey", &privkey_data, &privkey_data_size);
	if (ret != ASN1_SUCCESS) {
		printf ("Failed to read privkey\n");
		goto error;
	}
	printf ("privkey_data_size: %d\n", privkey_data_size);
	dump_hex (privkey_data, privkey_data_size);

	ret = 0;
error:
	asn1_delete_structure (&tpm2key);

	if (type_oid)
		free (type_oid);
	if (empty_auth_str)
		free (empty_auth_str);
	if (policy_data)
		free (policy_data);
	if (pubkey_data)
		free (pubkey_data);
	if (privkey_data)
		free (privkey_data);

	return ret;
}

int
main(int argc, char *argv[])
{
	char *keyname;
	FILE *keyfile;
	int keysize;
	uint8_t *content = NULL;
	size_t read_size;
	uint32_t parent;
	void *pubkey_data = NULL;
	int pubkey_size = 0;
	void *privkey_data = NULL;
	int privkey_size = 0;
	int ret;

	if (argc != 2) {
		printf ("Usage: %s key_file\n", argv[0]);
		return -1;
	}

	keyname = argv[1];

	keyfile = fopen (keyname, "r");
	if (keyfile == NULL) {
		printf ("Invalid file: %s\n", keyname);
		return -1;
	}

	fseek (keyfile, 0L, SEEK_END);
	keysize = ftell (keyfile);
	rewind (keyfile);

	content = malloc (keysize);
	if (content == NULL) {
		printf ("Failed to allocate memory\n");
		goto error;
	}

	read_size = fread (content, 1, keysize, keyfile);
	if (read_size != keysize) {
		printf ("Failed to read the file: %d\n", read_size);
		goto error;
	}

	ret = asn1_init ();
	if (ret != 0) {
		printf ("Failed to initialize TPM2Key ASN.1\n");
		goto error;
	}

/*
	ret = process_content (content, keysize);
	if (ret != 0) {
		printf ("Failed to process the key file\n");
		goto error;
	}
*/
	ret = grub_tpm2key_start_parsing (content, keysize);
	if (ret != 0) {
		printf ("Failed to process the key file\n");
		goto error;
	}

	ret = grub_tpm2key_get_parent (&parent);
	if (ret != 0)
		goto error;
	printf ("parent: %x\n", parent);

	ret = grub_tpm2key_get_pubkey (&pubkey_data, &pubkey_size);
	if (ret != 0)
		goto error;
	printf ("pubkey size: %d\n", pubkey_size);
	dump_hex (pubkey_data, pubkey_size);

	ret = grub_tpm2key_get_privkey (&privkey_data, &privkey_size);
	if (ret != 0)
		goto error;
	printf ("privkey size: %d\n", privkey_size);
	dump_hex (privkey_data, privkey_size);

	print_authpolicy ();

	grub_tpm2key_end_parsing ();

error:
	if (keyfile)
		fclose (keyfile);
	if (content)
		free (content);
	if (pubkey_data)
		free (pubkey_data);
	if (privkey_data)
		free (privkey_data);

	return 0;
}
