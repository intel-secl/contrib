/* Verify a quote issued by an AIK */

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include "safe_lib.h"

#ifndef BYTE
#define BYTE unsigned char
#endif

#ifndef UINT8
#define UINT8 unsigned char
#endif

#ifndef UINT16
#define UINT16 unsigned short
#endif

#ifndef UINT32
#define UINT32 unsigned
#endif

#ifndef TPM_API_ALG_ID_SHA1
#define TPM_API_ALG_ID_SHA1         ((UINT16)0x0004)
#endif

#ifndef TPM_API_ALG_ID_SHA256
#define TPM_API_ALG_ID_SHA256       ((UINT16)0x000B)
#endif

typedef struct {
        UINT16 size;
        BYTE *buffer;
} TPM2B_NAME;

typedef struct {
        UINT16 size;
        BYTE *buffer;
} TPM2B_DATA;

typedef struct {
        UINT16 size;
        BYTE *digest;
} TPM2B_DIGEST;

typedef struct {
        UINT16 hashAlg;
        UINT8 size;
        BYTE *pcrSelected;
} TPMS_PCR_SELECTION;

typedef struct {
        UINT16 signAlg;
        UINT16 hashAlg;
        UINT16 size;
        BYTE *signature;
} TPMT_SIGNATURE;


#define SHA1_SIZE 20 // 20 bytes
#define SHA256_SIZE 32 // 32 bytes
#define MAX_BANKS 3  // support up to 3 pcr banks

/* this is the header structure in the quote file -- Microsoft PCPtool uses */
typedef struct _PCP_PLATFORM_ATTESTATION_BLOB2 {
    UINT32 Magic;
    UINT32 Platform;
    UINT32 HeaderSize;
    UINT32 cbPcrValues;
    UINT32 cbQuote;
    UINT32 cbSignature;
    UINT32 cbLog;
    UINT32 PcrAlgorithmId;
} PCP_PLATFORM_ATTESTATION_BLOB2, *PPCP_PLATFORM_ATTESTATION_BLOB2;

typedef struct _PCP_PLATFORM_ATTESTATION_BLOB {
  UINT32 Magic;
  UINT32 Platform;
  UINT32 HeaderSize;
  UINT32 cbPcrValues;
  UINT32 cbQuote;
  UINT32 cbSignature;
  UINT32 cbLog;
} PCP_PLATFORM_ATTESTATION_BLOB, *PPCP_PLATFORM_ATTESTATION_BLOB;

int
main (int ac, char **av)
{
	FILE		*f_in;
	BYTE		*chal = NULL;
	UINT32		chalLen = 0;;
	BYTE		*quote = NULL;
	UINT32		quoteLen;
	RSA			*aikRsa;
	//UINT32		selectLen;
	//BYTE		*select;
	//UINT32		pcrLen;
	BYTE chalmd[32];
        BYTE md[SHA256_SIZE];
	BYTE		qinfo[8+20+20];
	char		*chalfile = NULL;
	int			pcr;
	int			pcri = 0;
	int			ind = 0;
	int			i,j;
	PPCP_PLATFORM_ATTESTATION_BLOB pAttestation;
        PPCP_PLATFORM_ATTESTATION_BLOB2 pAttestation2 = NULL;
	UINT32 cursor = 0;
	BYTE *pbPcrValues = NULL;
    	UINT32 cbPcrValues = 0;
    	BYTE *pbQuote = NULL;
    	UINT32 cbQuote = 0;
    	BYTE *pbSignature = NULL;
    	UINT32 cbSignature = 0;
    	BYTE *pbLog = NULL;
    	UINT32 cbLog = 0;
    	//BYTE *pbNonce = NULL;
    	BYTE quoteDigest[SHA1_SIZE] = {0};
    	//UINT32 cbQuoteDigest = 0;
    	UINT32 tpmVersion = 0;
    	UINT32 returnCode = 0;

	UINT32 index = 0;
	UINT32		pcrSize;
	UINT32		pcrPos;
	UINT32		concatSize;
        BYTE            *quoted = NULL;
        BYTE            *quotedInfo = NULL;
        //UINT16          quotedInfoLen;
        //UINT16          sigAlg;
        UINT16          hashAlg;
        //BYTE            *sig;
        BYTE            *recvNonce = NULL;
        UINT32          recvNonceLen;
        TPM2B_NAME      tpm2b_name;
        TPM2B_DATA      tpm2b_data;
        //UINT32          verifiedLen;
        UINT32          pcrBankCount;
        TPMS_PCR_SELECTION      pcr_selection[MAX_BANKS];
        TPM2B_DIGEST    tpm2b_digest;
        //TPMT_SIGNATURE  tpmt_signature;
        BYTE            pcrConcat[SHA256_SIZE * 24 * 3]; //allocate 3 SHA256 banks memory to accomodate possible combination
        BYTE            pcrsDigest[SHA256_SIZE];
        UINT32 digestSize = SHA1_SIZE;
        UINT16 pcrAlgId = TPM_API_ALG_ID_SHA1;


	if (ac == 5 && 0 == strcmp(av[1], "-c")) {
		chalfile = av[2];
		for (i=3; i<ac; i++)
			av[i-2] = av[i];
		ac -= 2;
	}

	if (ac != 3) {
		fprintf (stderr, "Usage: %s [-c challengefile] aikrsafile quotefile\n", av[0]);
		exit (1);
	}

	/* Read challenge file */

	if (chalfile) {
		if ((f_in = fopen (chalfile, "rb")) == NULL) {
			fprintf (stderr, "Unable to open file %s\n", chalfile);
			exit (1);
		}
		fseek (f_in, 0, SEEK_END);
		chalLen = ftell (f_in);
		fseek (f_in, 0, SEEK_SET);
		chal = malloc (chalLen);
  		if (chal == NULL) {
			fprintf (stderr, "Unable to allocate memory to read file %s\n", chalfile);
            fclose(f_in);
			exit (1);
		}
		if (fread (chal, 1, chalLen, f_in) != chalLen) {
			fprintf (stderr, "Unable to read file %s\n", chalfile);
            fclose(f_in);
			exit (1);
		}
		fclose (f_in);
		SHA1 (chal, chalLen, chalmd);
		free (chal);
        chal = NULL;
	} else {
		memset (chalmd, 0, sizeof(chalmd));
	}


	/* Read AIK from OpenSSL file */

	if ((f_in = fopen (av[1], "rb")) == NULL) {
		fprintf (stderr, "Unable to open file %s\n", av[1]);
		exit (1);
	}
	if ((aikRsa = PEM_read_RSA_PUBKEY(f_in, NULL, NULL, NULL)) == NULL) {
		fprintf (stderr, "Unable to read RSA file %s\n", av[1]);
        fclose (f_in);
		exit (1);
	}
	fclose (f_in);

	/* Read quote file */

	if ((f_in = fopen (av[2], "rb")) == NULL) {
		fprintf (stderr, "Unable to open file %s\n", av[2]);
		exit (1);
	}
	fseek (f_in, 0, SEEK_END);
	quoteLen = ftell (f_in);
	fseek (f_in, 0, SEEK_SET);
	quote = malloc (quoteLen);
  	if (quote == NULL) {
		fprintf (stderr, "Unable to allocate memory to read file %s\n", av[2]);
        fclose(f_in);
		returnCode = 1;
		goto badquote;
	}
	if (fread (quote, 1, quoteLen, f_in) != quoteLen) {
		fprintf (stderr, "Unable to read file %s\n", av[2]);
        fclose(f_in);
		returnCode = 1;
		goto badquote;
	}
	fclose (f_in);

	/* Parse quote file */
        pAttestation = (PPCP_PLATFORM_ATTESTATION_BLOB)quote;

        pAttestation2 = (PPCP_PLATFORM_ATTESTATION_BLOB2) quote;
        pcrAlgId = (UINT16) pAttestation2->PcrAlgorithmId;
        if (pcrAlgId == TPM_API_ALG_ID_SHA256) {
            digestSize = SHA256_SIZE;
        }

    // Unpack the attestation blob
    cursor = pAttestation->HeaderSize;       //to the beginning of PcrValues
    //printf("header size is: %d\n", cursor);
    tpmVersion = pAttestation->Platform;
    pbPcrValues = &quote[cursor];
    cbPcrValues = pAttestation->cbPcrValues;
    cursor += pAttestation->cbPcrValues;     //to the beginning of TPM_QUOTE_INFO2

    //printf("tpmVersion: %d\n", tpmVersion);

    if(pAttestation->cbQuote != 0)
    {
        pbQuote = &quote[cursor];
        cbQuote = pAttestation->cbQuote;
        cursor += pAttestation->cbQuote;     //to the beginning of Signature
    }
    
    if(pAttestation->cbSignature != 0)
    {
        pbSignature = &quote[cursor];
        cbSignature = pAttestation->cbSignature;
        cursor += pAttestation->cbSignature; //to the beginning of measurement log
    }
    
    pbLog = &quote[cursor];
    cbLog = pAttestation->cbLog;
    cursor += pAttestation->cbLog;           //to the end of buffer

    // Step 1: calculate the digest of the quote -- MSR PCP tool still uses SHA1 hash for signature
    SHA1(pbQuote, cbQuote, quoteDigest);

    // Step 2: Verify the signature with the public AIK
    if (1 != RSA_verify(NID_sha1, quoteDigest, sizeof(quoteDigest), pbSignature, cbSignature, aikRsa)) {
		fprintf (stderr, "Error, bad RSA signature in quote\n");
		returnCode = 2;
		goto badquote;
    }

    // validate nonce
    if (tpmVersion==2) {
        index = 0;
        quoted = pbQuote + index;
	// !!! the quote received from MSR pcptool does not contain the quoteInfoLen
        //quotedInfoLen = (*(UINT16*)quoted); // This is NOT in network order
        quotedInfo = quoted; // following is the TPMS_ATTEST structure as defined in tpm2.0 spec
        //printf("quoteInfoLen: %02x\n", quotedInfoLen);

        //qualifiedSigner -- skip the magic header and type -- not interested
        //index += 2;
        index += 6;

        // tpm2b_name
        tpm2b_name.size = ntohs(*(UINT16*)(quoted + index));
        index += 2;
        tpm2b_name.buffer = quoted + index;
        //printf("tpm2b_name size: %02x\n", tpm2b_name.size); //This is in Network Order

        //tpm2b_data
        index += tpm2b_name.size; // skip tpm2b_name
        tpm2b_data.size = ntohs(*(UINT16*)(quoted + index));
        recvNonceLen = tpm2b_data.size;
        //printf("Received Nonce Len: %02x\n", recvNonceLen); //This is in Network Order
        index += 2; // skip UINT16
        /* now compare the received nonce with the chal */
        tpm2b_data.buffer = quoted + index;
        recvNonce = tpm2b_data.buffer;
        index += tpm2b_data.size; // skip tpm2b_data
        // First verificaiton is to check if the received nonce matches the challenges sent

        if (memcmp(recvNonce, chalmd, chalLen) != 0) {
                fprintf(stderr, "Error in comparing the received nonce with the challenge");
		returnCode = 3;
                goto badquote;
        } 
	}

	// prepare to verify PCR digest
	index += 17; // skip over the TPMS_CLOCKINFO structure - Not interested
	index += 8;  // skip over the firmware info - Not interested
	/* TPMU_ATTEST with selected PCR banks and PCRs, and their hash
	 * tpms_quote_info tpml_pcr_selection	
	 *	count 			uint32	0x00000001	 4 bytes -indicates the number of tpms_pcr_slection array
	 *	tpms_pcr_selection	hash algorithm	uint16	2 bytes
	 *				size of bit map	uint8	1 byte
	 *				pcrSelect		size of bytes
	 *	tpms_pcr_selection		
	 *	...				
	 *	tpm2b_digest		size	0x0020	2 bytes	
	 *				digest	32 bytes of hash
	 */
	pcrBankCount = ntohl(*(UINT32*)(quoted + index));
	//printf("bank count: %02x\n", pcrBankCount);
	index += 4;
	if (pcrBankCount > MAX_BANKS) {
		fprintf(stderr, "number of PCR selection array in the quote is greater than %d", MAX_BANKS);
		returnCode = 3;
		goto badquote;
	}
	
	// processing the tpms_pcr_selection array  
	for (i=0; i<pcrBankCount; i++) {
		pcr_selection[i].hashAlg = ntohs(*(UINT16*)(quoted + index));
		//printf("pcr bank: %02x\n", pcr_selection[i].hashAlg);
		index += 2;
		pcr_selection[i].size = (*(UINT8*)(quoted + index));
		//printf("pcr bit size byte: %02x\n", pcr_selection[i].size);
		index += 1;
		pcr_selection[i].pcrSelected = quoted + index;
		index += pcr_selection[i].size;
	}
	
	//NOTE: currently we only limit the selection of one PCR bank for quote
	tpm2b_digest.size = ntohs(*(UINT16*)(quoted + index));
	//printf("digest size: %02x\n", tpm2b_digest.size);
	index += 2;
	tpm2b_digest.digest = quoted + index;
	
	// validate the PCR concatenated digest
	pcri=0; ind=0; concatSize=0; pcrPos=0;
	for (j=0; j<pcrBankCount; j++) {
		hashAlg = pcr_selection[j].hashAlg;
		if (hashAlg == 0x04)
			pcrSize = SHA1_SIZE;
		else if (hashAlg == 0x0B)
			pcrSize = SHA256_SIZE;
		else {
			fprintf (stderr, "Not supported PCR banks (%02x) in quote\n", hashAlg);
			returnCode = 3;
			goto badquote;
		}

		for (pcr=0; pcr < 8*pcr_selection[j].size; pcr++) {
			if (pcr_selection[j].pcrSelected[pcr/8] & (1 << (pcr%8))) {
				if ((pcrPos +pcrSize) < sizeof(pcrConcat)) {
					memcpy_s(pcrConcat+pcrPos, sizeof(pcrConcat)-pcrPos, pbPcrValues+pcr*pcrSize, pcrSize);
				}
				else {
					fprintf (stderr, "Error, not enough memory for PCRs digest checking\n");
					returnCode = 3;
					goto badquote;	
				}
				//pcri++;
				ind++;
				concatSize += pcrSize;
				pcrPos += pcrSize;
			}
		}
	}
	if (ind<1) {
		fprintf(stderr, "Error, no PCRs selected for quote\n");
		returnCode = 4;
		goto badquote;
	}

	memset(pcrsDigest, 0, sizeof(pcrsDigest));
	// Step 4: calculate the digest of the pcrValues -- MSR PCP tool still uses SHA1 hash for digest
	//SHA256(pcrConcat, concatSize, pcrsDigest);
	SHA1(pcrConcat, concatSize, pcrsDigest);
	if (memcmp(pcrsDigest, tpm2b_digest.digest, tpm2b_digest.size) != 0) {
		fprintf(stderr, "Error in comparing the concatenated PCR digest with the digest in quote");
		returnCode = 5;
		goto badquote;
	}

	if (pcrAlgId == TPM_API_ALG_ID_SHA256) {
        /* Print out PCR values */
            for (pcr = 0; pcr < 24; pcr++) {
                printf("%2d ", pcr);
                for (i = 0; i < 32; i++) {
                    printf("%02x", pbPcrValues[32 * pcri + i]);
                }
                printf("\n");
                pcri++;
            }
        }
        else 
        {
            for (pcr = 0; pcr < 24; pcr++) {
                printf("%2d ", pcr);
                for (i = 0; i < 20; i++) {
                    printf("%02x", pbPcrValues[20 * pcri + i]);
                }
                printf("\n");
                pcri++;
            }
        }

	fflush (stdout);
	fprintf (stderr, "Success!\n");

	returnCode = 0;

badquote:
	//fprintf (stderr, "Input AIK quote file incorrect format\n");
        
	//clean allocated memory
	if (quote != NULL) free(quote);
	//if (chal != NULL) free(chal);
	return returnCode;
}



