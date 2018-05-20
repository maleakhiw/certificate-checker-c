/**
 * Author: Maleakhi Agung Wijaya
 * Date: 19/05/2018
 * Computer Systems (COMP30023) Project 2 - TLS Certificate Checking
 */

 /********************************LIBRARY**************************************/

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/********************************CONSTANT**************************************/

#define MAX_DOMAIN_NAME 256
#define WILDCARD_POSITION 0
#define DOT_POSITION 1
#define WILDCARD_OFFSET 2
#define VALID 1
#define INVALID 0
#define BITS_CONVERSION 8
#define MINIMUM_KEY_LENGTH 2048
#define EXTENDED_KEY_AUTH "TLS Web Server Authentication"
#define NAME_BUFFER_LENGTH 1024

// Used for printing information (need to remove this before submitting)
// #define PRINT_DATE
#define PRINT_DOMAIN

/******************************FUNCTION*DECLARATION***************************/

int is_certificate_date_valid(X509* cert);
int is_domain_name_valid(X509 *cert, char *certificate_url);
int fill_san_array(STACK_OF(GENERAL_NAME) *san_names, char ***san_array);
void free_san_array(char ***san_array, int length_san_array);
int is_valid_wildcard_exist(char *str);
int check_single_name(char *single_name, char *host_name);
int check_san(char **san_array, int length_san_array, char *host_name);
int is_key_length_valid(X509 *cert);
int is_ca_false_valid(X509 *cert);
void ext_name_value(X509 *cert, int NID, char name_buffer[], char **value_buffer);
int is_extended_key_usage_valid(X509* cert);

/*********************************MAIN*FUNCTION********************************/

int main() {
    const char test_cert_example[] = "./cert-file2.pem";
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    int is_valid;

    /** Initialise open ssl and bio certificate */
    // Initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // Create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    // Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, test_cert_example)))
    {
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }
    // Read into cert which contains the X509 certificate and can be used to analyse the certificate
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
    {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    /** Testing validation of dates */
    // Read not before and not after date
    is_valid = is_certificate_date_valid(cert);
    #ifdef PRINT_DATE
    printf("Date Validation: %d\n", is_valid);
    #endif

    /** Domain name validation (CN & SAN) */
    is_valid = is_domain_name_valid(cert, "googl.com");
    #ifdef PRINT_DOMAIN
    printf("Domain name validation: %d\n", is_valid);
    #endif


    // int test = is_domain_name_valid(cert, "b*r.com");
    // char **san_array = (char **) malloc(sizeof(char *) * 3);
    // san_array[0] = (char *) malloc(sizeof(char) * (strlen("*.google.com") + 1));
    // strcpy(san_array[0], "*.google.com");
    // san_array[1] = (char *) malloc(sizeof(char) * (strlen("drive.google.co.au") + 1));
    // strcpy(san_array[1], "drive.google.co.au");
    // san_array[2] = (char *) malloc(sizeof(char) * (strlen("anon.com") + 1));
    // strcpy(san_array[2], "anon.com");
    //
    //
    // // char san_array[][256] = {"google.com.au", "*.google.com", "*.anonymous.com"};
    // // int i;
    // // for (i = 0; i < 3; i++) {
    // //     printf("%s\n",san_array[i]);
    // // }
    // int test = check_san(san_array, 3, "anon.com");
    // // int test = check_single_name("*.google.com.au", "drive.google.com.au");
    // printf("test: %d\n", test);

    /**************** Key Length validation ******************************/
    is_key_length_valid(cert);

    /**************** correct key usage (basic constraint + enhanced key usage) ******************************/

    // BASIC_CONSTRAINTS *bs;
    // // PROXY_CERT_INFO_EXTENSION *pci;
    // // ASN1_BIT_STRING *usage;
    // // ASN1_BIT_STRING *ns;
    // // EXTENDED_KEY_USAGE *extusage;
    // // X509_EXTENSION *ex;
    //
    // // int k;
    // // if (cert->ex_flags & EXFLAG_SET)
    // //     return;
    // // X509_digest(cert, EVP_sha1(), cert->sha1_hash, NULL);
    // // /* V1 should mean no extensions ... */
    // // if (!X509_get_version(cert))
    // //     cert->ex_flags |= EXFLAG_V1;
    // /* Handle basic constraints */
    // if ((bs = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL))) {
    //     // char *ca = ASN1_STRING_data(bs->ca);
    //     printf("basic constraint: %d\n", bs->ca);
    //     // if (bs->ca)
    //     //     cert->ex_flags |= EXFLAG_CA;
    //     // if (bs->pathlen) {
    //     //     if ((bs->pathlen->type == V_ASN1_NEG_INTEGER)
    //     //         || !bs->ca) {
    //     //         cert->ex_flags |= EXFLAG_INVALID;
    //     //         cert->ex_pathlen = 0;
    //     //     } else
    //     //         cert->ex_pathlen = ASN1_INTEGER_get(bs->pathlen);
    //     // } else
    //     //     cert->ex_pathlen = -1;
    //     BASIC_CONSTRAINTS_free(bs);
    //     // cert->ex_flags |= EXFLAG_BCONS;
    // }
    // int test_ca = is_ca_false_valid(cert);
    // printf("CA: FALSE is %d\n", test_ca);

    // Extract extended key usage
    // STACK_OF(ASN1_OBJECT) *extended_key_usage = (STACK_OF(ASN1_OBJECT) *) X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    // const char *key_usage_value = NULL;
    // int usage_id = 0;
    // // Get extended key usage value
    // while (sk_ASN1_OBJECT_num(extended_key_usage) > 0) {
    //     // Get everything
    //     usage_id = OBJ_obj2nid(sk_ASN1_OBJECT_pop(extended_key_usage));
    //     key_usage_value = OBJ_nid2sn(usage_id);
    //     printf("ext key usage: %s \n", key_usage_value);
    // }
    // char extension_name[1024];
    // char *extension_value = "hello";
    // get_extension_name_value(cert, NID_ext_key_usage, extension_name, &extension_value);
    //
    // printf("Extension %s: %s\n", extension_name, extension_value);


    /********************************************************************/

    // // Analysing the certificate value
    // cert_issuer = X509_get_issuer_name(cert);
    // char issuer_cn[256] = "Issuer CN NOT FOUND";
    // X509_NAME_get_text_by_NID(cert_issuer, NID_commonName, issuer_cn, 256);
    // printf("Issuer CommonName:%s\n", issuer_cn);

    // List of extensions available at https://www.openssl.org/docs/man1.1.0/crypto/X509_REVOKED_get0_extensions.html
    // Need to check extension exists and is not null
    // X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
    // ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    // char buff[1024];
    // OBJ_obj2txt(buff, 1024, obj, 0);
    // printf("Extension:%s\n", buff);
    //
    // BUF_MEM *bptr = NULL;
    // char *buf = NULL;
    //
    // BIO *bio = BIO_new(BIO_s_mem());
    // if (!X509V3_EXT_print(bio, ex, 0, 0))
    // {
    //     fprintf(stderr, "Error in reading extensions");
    // }
    // BIO_flush(bio);
    // BIO_get_mem_ptr(bio, &bptr);
    //
    // //bptr->data is not NULL terminated - add null character
    // buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    // memcpy(buf, bptr->data, bptr->length);
    // buf[bptr->length] = '\0';
    //
    // //Can print or parse value
    // printf("%s\n", buf);
    //
    // // Now buff contain the extended key usage, validation
    // char *ret = strstr(buf, EXTENDED_KEY_AUTH);
    // if (ret == NULL) {
    //     printf("invalid");
    // }
    // else {
    //     printf("valid");
    // }
    //
    // free(buf);
    // char name_buffer[NAME_BUFFER_LENGTH];
    // char *value_buffer;
    //
    // ext_name_value(cert, NID_ext_key_usage, name_buffer, &value_buffer);
    // printf("The value of name buffer is %s\n", name_buffer);
    // printf("The value of value_buffer is %s\n", value_buffer);
    //
    // free(value_buffer);
    // int test_ext = is_extended_key_usage_valid(cert);
    // printf("test ext: %d\n", test_ext);

    X509_free(cert);
    BIO_free_all(certificate_bio);
    // BIO_free_all(bio);
    return 0;
}

/*******************************FUNCTIONS**************************************/

/**
 * Used to check whether the certificate date is currently valid
 * @param cert: certificates
 * @return VALID, INVALID
 */
int is_certificate_date_valid(X509 *cert) {
	int day, sec;
	ASN1_TIME *not_before = NULL, *not_after = NULL, *today = NULL;

	not_before = X509_get_notBefore(cert);
	not_after = X509_get_notAfter(cert);

    #ifdef PRINT_DATE
    BIO *b;
    b = BIO_new_fp(stdout, BIO_NOCLOSE);

    printf("Not before date: ");
    ASN1_TIME_print(b, not_before);
    printf("\n");

    printf("Not after date: ");
    ASN1_TIME_print(b, not_after);
    printf("\n");

    BIO_free(b);
    #endif

	// Current date should be between the not before and not after date
	// Check not_before first with today's date, immediately return 0 (invalid)
	// if today's date is before not_before date
	if (!ASN1_TIME_diff(&day, &sec, not_before, today)) {
		fprintf(stderr, "Invalid time format.");
		exit(EXIT_FAILURE);
	}

	// If today's date is before not_before date
	if (day < 0 || sec < 0) {
		return INVALID;
	}

	// Check not_after date with today's date, today's date should be before
	// not_after date
	if (!ASN1_TIME_diff(&day, &sec, today, not_after)) {
		fprintf(stderr, "Invalid time format.");
		exit(EXIT_FAILURE);
	}

	// If not_after date is before today's date
	if (day < 0 || sec < 0) {
		return INVALID;
	}

	return VALID; // it is valid if within range
}

/**
 * Used to check whether the domain name of the certificate is valid
 * @param cert: certificate used to extract subject SAN and subject CN
 * @param certificate_url: URL from which certificates belongs (column 2)
 * @return VALID, INVALID
 */
int is_domain_name_valid(X509 *cert, char *certificate_url) {
    int is_valid;

	// Variable for CN
	X509_NAME *cert_subject = NULL;
	char common_name[MAX_DOMAIN_NAME] = "Subject CN NOT FOUND.";

	// Variable for SAN
	STACK_OF(GENERAL_NAME) *san_names = NULL;
	int length_san_array;

	/* Process to get Common Name */
	cert_subject = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(cert_subject, NID_commonName, common_name,
        MAX_DOMAIN_NAME);

	#ifdef PRINT_DOMAIN
	printf("Subject common name: %s\n", common_name);
	#endif

	/* Process to get SAN */
	san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

	/** Validity check */
	// If san names not null, will process san names in addition to common name
	if (san_names != NULL) {
        // Create and fill san_array
        char **san_array = NULL;
        length_san_array = fill_san_array(san_names, &san_array);
		sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

		#ifdef PRINT_DOMAIN
        int i;
		for (i = 0; i < length_san_array; i++) {
			printf("SAN: %s\n", san_array[i]);
		}
		#endif

		// Check validity by comparing with both common name and san name
        is_valid = check_single_name(common_name, certificate_url) ||
					check_san(san_array, length_san_array, certificate_url);

        // Free memory used by san array
        free_san_array(&san_array, length_san_array);
	}
	// If there is no san name
	else {
		// Just compare with common name
		is_valid = check_single_name(common_name, certificate_url);
	}

    return is_valid;
}

/**
 * Used to fill san_array with san
 * @param san_names: san available in STACK_OF(GENERAL_NAME) * format
 * @param san_array: array that will be used as storage of san
 * @return length_san_array: elements filled in san_array
 */
int fill_san_array(STACK_OF(GENERAL_NAME) *san_names, char ***san_array) {
    int i, length_san_array;
    int san_names_count = sk_GENERAL_NAME_num(san_names);

    // Array used to hold SAN
    *san_array = (char **) malloc(sizeof(char *) * san_names_count);
    // Iterate and fill the SAN array
    for (i=0; i<san_names_count; i++) {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

        if (current_name->type == GEN_DNS) {
            // Copy san name to san array
            char *dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);
            (*san_array)[i] = (char *) malloc(sizeof(char) * (strlen(dns_name)+1)); // extra nullbyte
            strcpy((*san_array)[i], dns_name);
        }
    }
    length_san_array = i;
    return length_san_array;
}

/**
 * Free element used by san_array
 * @param san_array: array to be freed
 * @param length_san_array: length of filled san_array
 */
void free_san_array(char ***san_array, int length_san_array) {
    int i;

    // Iterate inner san array
    for (i=0; i < length_san_array; i++) {
        free((*san_array)[i]);
        (*san_array)[i] = NULL;
    }

    // Free the element itself
    free(*san_array);
    *san_array = NULL;
}

/**
 * Used to check whether a VALID (leftmost) wildcard exist in a particular string
 * @param str: string to be checked
 * @return VALID, INVALID
 */
int is_valid_wildcard_exist(char *str) {
	assert(str != NULL);

	// If leftmost only wildcard and not only containing wildcard
	if (str[WILDCARD_POSITION] == '*' && strlen(str) > WILDCARD_OFFSET &&
        str[DOT_POSITION] == '.') {
		return VALID;
	}
	return INVALID;
}

/**
 * Used to compare host name/ certificate_url with single name
 * @param single_name: string representing a name
 * @param host_name: string representing host name
 * @return VALID: host name == common name, INVALID: otherwise
 */
int check_single_name(char *single_name, char *host_name) {
	int i, offset_index_host = 0;
	char *offset_single_name = NULL, *offset_host_name = NULL;

	 // If no wildcard exist, just compare normally
	 if (!is_valid_wildcard_exist(single_name)) {
		 // If the same, then it is valid
		 if (strcmp(single_name, host_name) == 0) {
			 return VALID;
		 }
		 else {
			 return INVALID;
		 }
	 }
	 // Otherwise wildcard exist, process differently
	 else {
		 // Offset name that will be compared without the wildcard
		 offset_single_name = (single_name + WILDCARD_OFFSET);

		 // Search for the first dot location and get everything after the first dot
		 for (i = 0; i < strlen(host_name); i++) {
			 if (host_name[i] == '.') {
                 // Handle condition when the first element is .
                 if (i == 0) {
                     return INVALID;
                 }
				 offset_index_host = i + 1;
				 break;
			 }
		 }
		 offset_host_name = (host_name + offset_index_host);

		 // Perform comparison
		 if (strcmp(offset_single_name, offset_host_name) == 0) {
			 return VALID;
		 }
		 else {
			 return INVALID;
		 }
	 }
 }

/**
 * Used to compare SAN with host name/ certificate_url
 * @param san_name: array of strings
 * @param length_san_array: length of san_array
 * @param host_name: string representing host name
 * @return VALID if host name is contain in the san name, INVALID otherwise
 */
int check_san(char **san_array, int length_san_array, char *host_name) {
	int i;

	// Iterate through san_array and compare with host name
	for (i = 0; i < length_san_array; i++) {
		// If there is an alternative name that match with host name, VALID
		if (check_single_name(san_array[i], host_name) == VALID) {
			return VALID;
		}
	}
	return INVALID; // cannot find anything similar
}

/**
 * Check validity of RSA key length
 * @param cert: certificate
 * @return VALID if (>= 2048 bits), INVALID otherwise
 */
int is_key_length_valid(X509 *cert) {
	EVP_PKEY *public_key = X509_get_pubkey(cert);
	RSA *rsa = EVP_PKEY_get1_RSA(public_key);
	int size = RSA_size(rsa);
	int size_in_bits = size * BITS_CONVERSION;

	int is_valid; // capture validity result

	// Perform check of >= 2048
	if (size_in_bits >= MINIMUM_KEY_LENGTH) {
		is_valid = VALID;
	}
	else {
		is_valid = INVALID;
	}

	RSA_free(rsa);

	return is_valid;
}

/**
 * Used to check whether CA: FALSE
 * @param cert: certificate
 * @return VALID if CA: FALSE , otherwise INVALID
 */
int is_ca_false_valid(X509 *cert) {
    BASIC_CONSTRAINTS *basic_constraint;
    basic_constraint = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    int is_valid;

    // Check if there is basic constraint extension
    if (!basic_constraint) {
        return INVALID;
    }

    // Perform analysis, only valid if CA: FALSE
    // Condition when CA: FALSE
    if ((basic_constraint -> ca) == 0) {
        is_valid = VALID;
    }
    else {
        is_valid = INVALID;
    }

    BASIC_CONSTRAINTS_free(basic_constraint);
    return is_valid;
}

/**
 * Used to check whether extended key usage is valid (contain EXTENDED_KEY_AUTH)
 * @param cert: certificate
 * @return VALID if contain TLS Web Server Authentication, INVALID otherwise
 */
int is_extended_key_usage_valid(X509* cert) {
    char usage_buffer[NAME_BUFFER_LENGTH];
    char *value_buffer;
    char *ret;
    int is_valid;

    // Get the usage buffer name and value of the extended usage
    ext_name_value(cert, NID_ext_key_usage, usage_buffer, &value_buffer);

    #ifdef DEBUG
    printf("The value of name buffer is %s\n", name_buffer);
    printf("The value of value_buffer is %s\n", value_buffer);
    #endif

    // Check using substring method with value_buffer
    ret = strstr(value_buffer, EXTENDED_KEY_AUTH);
    if (ret == NULL) {
        is_valid = INVALID;
    }
    else {
        is_valid = VALID;
    }

    free(value_buffer);
    return is_valid;
}

/**
 * Used to get extension name and value (most of the code using Chris Culnane example)
 * @param cert: certificate
 * @param NID: nid of the extensions
 * @param extension_name_ptr: pointer to extension name that will be filled
 * @param extension_value_ptr: pointer to extension value that will be filled
 */
void ext_name_value(X509 *cert, int NID, char name_buffer[], char **value_buffer) {
    // Need to check extension exists and is not null
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert,
        NID, -1));
    // If extension is null then immediately return and will be invalid
    if (ex == NULL) {
        return;
    }

    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    OBJ_obj2txt(name_buffer, NAME_BUFFER_LENGTH, obj, 0);

    // Process the value of the extension
    BUF_MEM *bptr = NULL;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    // Store the value of extension in value_buffer
    // bptr->data is not NULL terminated - add null character
    *value_buffer = (char *) malloc((bptr->length + 1) * sizeof(char));
    memcpy(*value_buffer, bptr->data, bptr->length);
    (*value_buffer)[bptr->length] = '\0';

    // Free the bio
    BIO_free_all(bio);
}
