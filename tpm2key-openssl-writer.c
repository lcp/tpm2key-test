/* gcc -lcrypto tpm2key-openssl-writer.c -o tpm2key-openssl-writer */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include "tpm2-asn.h"

const uint32_t test_parent = 0x40000001;
const char test_pubkey[] = {0x00, 0x00, 0x00, 0x01};
const char test_privkey[] = {0x11, 0x11, 0x11, 0x22, 0x22, 0x22};
const char *outfile = "test-openssl.der";

int fake_cc = 0x16;
char fake_pol[] = {0x33, 0x33, 0x33};

void
tpm2_free_policy (STACK_OF(TSSOPTPOLICY) *sk)
{
	TSSOPTPOLICY *policy;

	if (sk)
		while ((policy = sk_TSSOPTPOLICY_pop(sk)))
			TSSOPTPOLICY_free(policy);

	sk_TSSOPTPOLICY_free(sk);
}

int
tpm2key_add_authpolicy (TSSPRIVKEY *tpm2key, char *name, int cmd, void *cmd_policy,
			int cmd_policy_len)
{
	TSSAUTHPOLICY *ap;
	TSSOPTPOLICY *policy;

	ap = TSSAUTHPOLICY_new ();
	ap->name = ASN1_UTF8STRING_new ();
	ap->policy = sk_TSSOPTPOLICY_new_null ();
	policy = TSSOPTPOLICY_new ();

	ASN1_STRING_set(ap->name, name, strlen (name));

	ASN1_INTEGER_set (policy->CommandCode, cmd);
	ASN1_STRING_set (policy->CommandPolicy, cmd_policy, cmd_policy_len);
	sk_TSSOPTPOLICY_push(ap->policy, policy);

	if (!tpm2key->authPolicy)
		tpm2key->authPolicy = sk_TSSAUTHPOLICY_new_null ();

	/* Insert the new auth policy in the beginning of the sequence */
	sk_TSSAUTHPOLICY_unshift(tpm2key->authPolicy, ap);

	return 0;
}

TSSPRIVKEY *
tpm2key_basekey (const int parent, const void *pubkey, const int pubkey_size,
	         const void *privkey, const int privkey_size)
{
	TSSPRIVKEY *key;

	key = TSSPRIVKEY_new ();
	if (key == NULL)
		return NULL;

	key->type = OBJ_txt2obj (OID_sealedData, 1);
	key->emptyAuth = 1;
	key->parent = ASN1_INTEGER_new ();
	ASN1_INTEGER_set (key->parent, parent);

	key->pubkey = ASN1_OCTET_STRING_new ();
	ASN1_STRING_set (key->pubkey, pubkey, pubkey_size);
	key->privkey = ASN1_OCTET_STRING_new ();
	ASN1_STRING_set (key->privkey, privkey, privkey_size);

	return key;
}

int
write_tpm2key (TSSPRIVKEY *key, const char *filename)
{
	BIO *outb;
	unsigned char *out_buf = NULL;
	int out_buf_size;

	outb = BIO_new_file(filename, "w");

	out_buf_size = i2d_TSSPRIVKEY (key, &out_buf);
	if (out_buf_size < 0) {
		printf ("Failed to encode the key\n");
		return -1;
	}
	BIO_write (outb, out_buf, out_buf_size);

	BIO_free (outb);
	return 0;
}

int
main ()
{
	TSSPRIVKEY *key = NULL;

	key = tpm2key_basekey (test_parent, test_pubkey, sizeof(test_pubkey),
			       test_privkey, sizeof(test_privkey));
	if (key == NULL) {
		printf ("NULL TSSPRIVKEY\n");
		return -1;
	}

	tpm2key_add_authpolicy (key, "test1", fake_cc, fake_pol, sizeof (fake_pol));
	tpm2key_add_authpolicy (key, "test2", fake_cc, fake_pol, sizeof (fake_pol));

	write_tpm2key (key, outfile);

	return 0;
}

IMPLEMENT_ASN1_FUNCTIONS(TSSOPTPOLICY)
IMPLEMENT_ASN1_FUNCTIONS(TSSAUTHPOLICY)
IMPLEMENT_ASN1_FUNCTIONS(TSSLOADABLE)
IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY)
IMPLEMENT_PEM_write_bio(TSSLOADABLE, TSSLOADABLE, TSSLOADABLE_PEM_STRING, TSSLOADABLE)
IMPLEMENT_PEM_read_bio(TSSLOADABLE, TSSLOADABLE, TSSLOADABLE_PEM_STRING, TSSLOADABLE)
IMPLEMENT_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY)
IMPLEMENT_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY)

ASN1_SEQUENCE(TSSOPTPOLICY) = {
	ASN1_EXP(TSSOPTPOLICY, CommandCode, ASN1_INTEGER, 0),
	ASN1_EXP(TSSOPTPOLICY, CommandPolicy, ASN1_OCTET_STRING, 1)
} ASN1_SEQUENCE_END(TSSOPTPOLICY)

ASN1_SEQUENCE(TSSAUTHPOLICY) = {
	ASN1_EXP_OPT(TSSAUTHPOLICY, name, ASN1_UTF8STRING, 0),
	ASN1_EXP_SEQUENCE_OF(TSSAUTHPOLICY, policy, TSSOPTPOLICY, 1)
} ASN1_SEQUENCE_END(TSSAUTHPOLICY)

ASN1_SEQUENCE(TSSLOADABLE) = {
	ASN1_SIMPLE(TSSLOADABLE, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TSSLOADABLE, emptyAuth, ASN1_BOOLEAN, 0),
	ASN1_EXP_OPT(TSSLOADABLE, parent, ASN1_INTEGER, 1),
	ASN1_EXP_OPT(TSSLOADABLE, pubkey, ASN1_OCTET_STRING, 2),
	ASN1_EXP_SEQUENCE_OF_OPT(TSSLOADABLE, policy, TSSOPTPOLICY, 3),
	ASN1_SIMPLE(TSSLOADABLE, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSLOADABLE)

ASN1_SEQUENCE(TSSPRIVKEY) = {
	ASN1_SIMPLE(TSSPRIVKEY, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TSSPRIVKEY, emptyAuth, ASN1_BOOLEAN, 0),
	ASN1_EXP_SEQUENCE_OF_OPT(TSSPRIVKEY, policy, TSSOPTPOLICY, 1),
	ASN1_EXP_OPT(TSSPRIVKEY, secret, ASN1_OCTET_STRING, 2),
	ASN1_EXP_SEQUENCE_OF_OPT(TSSPRIVKEY, authPolicy, TSSAUTHPOLICY, 3),
	ASN1_SIMPLE(TSSPRIVKEY, parent, ASN1_INTEGER),
	ASN1_SIMPLE(TSSPRIVKEY, pubkey, ASN1_OCTET_STRING),
	ASN1_SIMPLE(TSSPRIVKEY, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSPRIVKEY)
