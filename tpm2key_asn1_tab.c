#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <libtasn1.h>

const asn1_static_node tpm2key_asn1_tab[] = {
  { "TPM2KEY", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "TPMPolicy", 1610612741, NULL },
  { "CommandCode", 1610620931, NULL },
  { NULL, 2056, "0"},
  { "CommandPolicy", 536879111, NULL },
  { NULL, 2056, "1"},
  { "TPMAuthPolicy", 1610612741, NULL },
  { "Name", 1610637346, NULL },
  { NULL, 2056, "0"},
  { "Policy", 536879115, NULL },
  { NULL, 1073743880, "1"},
  { NULL, 2, "TPMPolicy"},
  { "TPMKey", 536870917, NULL },
  { "type", 1073741836, NULL },
  { "emptyAuth", 1610637316, NULL },
  { NULL, 2056, "0"},
  { "policy", 1610637323, NULL },
  { NULL, 1073743880, "1"},
  { NULL, 2, "TPMPolicy"},
  { "secret", 1610637319, NULL },
  { NULL, 2056, "2"},
  { "authPolicy", 1610637323, NULL },
  { NULL, 1073743880, "3"},
  { NULL, 2, "TPMAuthPolicy"},
  { "parent", 1073741827, NULL },
  { "pubkey", 1073741831, NULL },
  { "privkey", 7, NULL },
  { NULL, 0, NULL }
};
