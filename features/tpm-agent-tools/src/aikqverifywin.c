/* Verify a quote issued by an AIK */
/* See aikquote.c for format of quote data file */

/*
 * Copyright (c) 2009 Hal Finney
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <memory.h>
//#include <trousers/tss.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include "safe_lib.h"


#ifndef BYTE
#define BYTE unsigned char
#endif

#ifndef UINT16
#define UINT16 unsigned short
#endif

#ifndef UINT32
#define UINT32 unsigned
#endif

#define SHA1_SIZE 20 // 20 bytes

/* this is the header structure in the quote file -- Microsoft PCPtool uses */
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
	BYTE		*chal;
	UINT32		chalLen;
	BYTE		*quote;
	UINT32		quoteLen;
	RSA			*aikRsa;
	UINT16		selectLen;
	//UINT32		sigLen;
	//BYTE		*sig;
	BYTE		chalmd[20];
	BYTE		md[20];
	BYTE		qinfo[8+20+20];
	char		*chalfile = NULL;
	int			pcr;
	int			pcri = 0;
	int			ind = 0;
	int			i;
	PPCP_PLATFORM_ATTESTATION_BLOB pAttestation;
	UINT32 cursor = 0;
	BYTE *pbPcrValues = NULL;
    UINT32 cbPcrValues = 0;
    BYTE *pbQuote = NULL;
    UINT32 cbQuote = 0;
    BYTE *pbSignature = NULL;
    UINT32 cbSignature = 0;
    BYTE *pbLog = NULL;
    UINT32 cbLog = 0;
    BYTE *pbNonce = NULL;
    BYTE quoteDigest[20] = {0};
	
	UINT32 index = 0;
	UINT32 returnCode = 0;
	UINT32		pcrSize = SHA1_SIZE;
	UINT32		concatSize;
	UINT32		concatSizeHost;
	UINT32		compositeSize;
	BYTE            *quoted = NULL;
	BYTE		*pcrSelect;
	BYTE		*compositeHash;
	BYTE            pcrConcat[SHA1_SIZE * 24];
	BYTE            pcrsDigest[SHA1_SIZE];
	BYTE		pcrComposite[SHA1_SIZE * 24 + 9];

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
			fprintf (stderr, "Unable to allocate memory\n");
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
		fprintf (stderr, "Unable to allocate memory for quote\n");
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

    // Unpack the attestation blob
    cursor = pAttestation->HeaderSize;       //to the beginning of PcrValues
    pbPcrValues = &quote[cursor];
    cbPcrValues = pAttestation->cbPcrValues;
    cursor += pAttestation->cbPcrValues;     //to the beginning of TPM_QUOTE_INFO2
    if(pAttestation->cbQuote != 0)
    {
        pbQuote = &quote[cursor];
        cbQuote = pAttestation->cbQuote;
        pbNonce = &pbQuote[2+4];
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

    // Step 1: calculate the digest of the quote
    SHA1(pbQuote, cbQuote, quoteDigest);

    // Step 2: Validate the nonce
    if (pbNonce != NULL && (memcmp(chalmd, pbNonce, 20) != 0)) {
    	fprintf (stderr, "Error, bad Nonce in quote\n");
		returnCode = 2;
		goto badquote;
    }

    // Step 3: Verify the signature with the public AIK
	if (1 != RSA_verify(NID_sha1, quoteDigest, sizeof(quoteDigest), pbSignature, cbSignature, aikRsa)) {
		fprintf (stderr, "Error, bad RSA signature in quote\n");
		returnCode = 3;
		goto badquote;
	}
	
	index = 0;
	quoted = pbQuote + index;
	
	// prepare to verify PCR digest
	index += 6; // skip over the TPM_STRUCTURE_TAG structure - Not interested
	index += 20;  // skip over the nonce info - Already validated
	/* TPM_PCR_INFO_SHORT with selected PCR localities and PCRs, and their hash
	 *	tpm_pcr_selection	size of bit map	uint16	2 bytes
	 *				pcrSelect		size of bytes
	 *	tpm_pcr_selection		
	 *	...				
	 *	tpm_composite_hash		digest	20 bytes of hash
	 */
	selectLen = ntohs(*(UINT16*)(quoted + index));
	//printf("select len: %02x\n", selectLen);
	index += 2;
	pcrSelect = quoted + index;
	index += selectLen;
	index += 1; // skip over the locality selection - Not interested
	compositeHash = quoted + index;
	
	// validate the PCR concatenated digest
	pcri=0; ind=0; concatSize=0;
	for (pcr=0; pcr < 8*selectLen; pcr++) {
		if (pcrSelect[pcr/8] & (1 << (pcr%8))) {
			if ((concatSize +pcrSize) < sizeof(pcrConcat)) {
				memcpy_s(pcrConcat+concatSize, sizeof(pcrConcat)-concatSize, pbPcrValues+pcr*pcrSize, pcrSize);
			}
			else {
				fprintf (stderr, "Error, not enough memory for PCRs digest checking\n");
				returnCode = 3;
				goto badquote;	
			}
			//pcri++;
			ind++;
			concatSize += pcrSize;
		}
	}
	if (ind<1) {
		fprintf(stderr, "Error, no PCRs selected for quote\n");
		returnCode = 4;
		goto badquote;
	}

	compositeSize=0;
	memcpy_s(pcrComposite, sizeof(pcrComposite), quoted+26, 2+selectLen); // copying TPM_PCR_SELECTION
	compositeSize += (2+selectLen);

	concatSizeHost = ntohl(concatSize);
	memcpy_s(pcrComposite+compositeSize, sizeof(pcrComposite)-compositeSize, (BYTE*)(&concatSizeHost), 4); // copying size of pcrConcat
	compositeSize += 4;

	memcpy_s(pcrComposite+compositeSize, sizeof(pcrComposite)-compositeSize, pcrConcat, concatSize); // copying pcrConcat
	compositeSize += concatSize;

	memset(pcrsDigest, 0, sizeof(pcrsDigest));
	// Step 4: calculate the digest of the pcrValues -- MSR PCP tool still uses SHA1 hash for digest
	SHA1(pcrComposite, compositeSize, pcrsDigest);
	if (memcmp(pcrsDigest, compositeHash, SHA1_SIZE) != 0) {
		fprintf(stderr, "Error in comparing the concatenated PCR digest with the digest in quote");
		returnCode = 5;
		goto badquote;
	}

	/* Print out PCR values */
	for (pcr=0; pcr < 24; pcr++) {
		//if (select[pcr/8] & (1 << (pcr%8))) {
			printf ("%2d ", pcr);
			for (i=0; i<20; i++) {
				printf ("%02x", pbPcrValues[20*pcri+i]);
			}
			printf ("\n");
			pcri++;
		//}
	}

	fflush (stdout);
	fprintf (stderr, "Success!\n");

	returnCode = 0;

badquote:
	//fprintf (stderr, "Input AIK quote file incorrect format\n");
        
	//clean allocated memory
	if (quote != NULL) free(quote);
	return returnCode;
}



