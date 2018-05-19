/**
 * Author: Maleakhi Agung Wijaya
 * Date: 19/05/2018
 * Computer Systems (COMP30023) Project 2
 */

 /********************************LIBRARY**************************************/

#include <openssl/x509.h>
#include <openssl/x509v3.h>
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
#define WILDCARD_OFFSET 2

#define VALID 1
#define INVALID 0

#define BITS_CONVERSION 8
#define MINIMUM_KEY_LENGTH 2048

// #define DEBUG // used for debugging purposes

/******************************FUNCTION*DECLARATION***************************/

int is_certificate_date_valid(X509* cert);
int is_domain_name_valid(X509 *cert, char *certificate_url);
int is_valid_wildcard_exist(char *str);
int check_single_name(char *single_name, char *host_name);
int check_san(char **san_array, int length_san_array, char *host_name);
int is_key_length_valid(X509 *cert);

/** Testing date */
// // Used for printing
// #define DATE_LEN 128
//
// int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len)
// {
// 	int rc;
// 	BIO *b = BIO_new(BIO_s_mem());
// 	rc = ASN1_TIME_print(b, t);
// 	if (rc <= 0) {
// 		// log_error("fetchdaemon", "ASN1_TIME_print failed or wrote no data.\n");
// 		BIO_free(b);
// 		return EXIT_FAILURE;
// 	}
// 	rc = BIO_gets(b, buf, len);
// 	if (rc <= 0) {
// 		// log_error("fetchdaemon", "BIO_gets call failed to transfer contents to buf");
// 		BIO_free(b);
// 		return EXIT_FAILURE;
// 	}
// 	BIO_free(b);
// 	return EXIT_SUCCESS;
// }

// int check_valid_date()

/*********************************MAIN*FUNCTION********************************/

int main() {
    const char test_cert_example[] = "./cert-file2.pem";
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    // X509_NAME *cert_issuer = NULL;
    // X509_CINF *cert_inf = NULL;
    // ASN1_TIME *not_before = NULL; // must not be freed up by docs
    // ASN1_TIME *not_after = NULL; // must not be freed up by docs
    // STACK_OF(X509_EXTENSION) * ext_list;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO
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
    /************** Testing Date Validity ***************/

    /** Testing date */
    // struct tm time = {};
    // time.tm_mday = 1;
    // time.tm_mon = 4;
    // time.tm_year = 130;
    //
    // time_t future_time = mktime(&time);
    // ASN1_TIME * future_date = ASN1_TIME_set(NULL, future_time);
    //
    // char not_after_str[DATE_LEN];
    // convert_ASN1TIME(future_date, not_after_str, DATE_LEN);
    // printf("Date not after: %s\n", not_after_str);

    // char not_before_str[DATE_LEN];
    // convert_ASN1TIME(not_before, not_before_str, DATE_LEN);
    // printf("Date not before: %s\n", not_before_str);

    // Read not before and not after date
    is_certificate_date_valid(cert);
    #ifdef DEBUG
    printf("The certificates is %d\n", validity);
    #endif

    /**************** Domain Name validation ******************************/

    int test = is_domain_name_valid(cert, "b*r.com");
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
    printf("test: %d\n", test);

    /********************************************************************/

    // // // Analysing the certificate value
    // cert_issuer = X509_get_issuer_name(cert);
    // char issuer_cn[256] = "Issuer CN NOT FOUND";
    // X509_NAME_get_text_by_NID(cert_issuer, NID_commonName, issuer_cn, 256);
    // printf("Issuer CommonName:%s\n", issuer_cn);
    //
    // //List of extensions available at https://www.openssl.org/docs/man1.1.0/crypto/X509_REVOKED_get0_extensions.html
    // //Need to check extension exists and is not null
    // X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1));
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

    X509_free(cert);
    BIO_free_all(certificate_bio);
    // BIO_free_all(bio);
    // free(buf);

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
	// Variable for CN
	X509_NAME *cert_subject = NULL;
	char common_name[MAX_DOMAIN_NAME] = "Subject CN NOT FOUND.";

	// Variable for SAN
	STACK_OF(GENERAL_NAME) *san_names = NULL;
	int san_names_count, length_san_array, i;

	/* Process to get Common Name */
	cert_subject = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(cert_subject, NID_commonName, common_name, MAX_DOMAIN_NAME);

	#ifdef DEBUG
	printf("Subject common name: %s\n", common_name);
	#endif

	/* Process to get SAN */
	san_names = X509_get_ext_d2i((X509 *) cert, NID_subject_alt_name, NULL, NULL);

	/** Validity check */
	// If san names not null, we will process san names in addition to common name
	if (san_names != NULL) {
		san_names_count = sk_GENERAL_NAME_num(san_names);

		// Array used to hold SAN
		char **san_array = (char **) malloc(sizeof(char *) * san_names_count);
		// Iterate and fill the SAN array
		for (i=0; i<san_names_count; i++) {
			const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

			if (current_name->type == GEN_DNS) {
				// Current name is a DNS name, let's check it
				char *dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);
				san_array[i] = (char *) malloc(sizeof(char) * (strlen(dns_name) + 1)); // extra nullbyte
				strcpy(san_array[i], dns_name);
			}
		}
		length_san_array = i; // elements filled
		sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

		#ifdef DEBUG
		for (i = 0; i < length_san_array; i++) {
			printf("SAN: %s\n", san_array[i]);
		}
		#endif

		// Check validity by comparing with both common name and san name
		return (check_single_name(common_name, certificate_url) ||
					check_san(san_array, length_san_array, certificate_url));
	}
	// If there is no san name
	else {
		// Just compare with common name
		return check_single_name(common_name, certificate_url);
	}
}

/**
 * Used to check whether a VALID (leftmost) wildcard exist in a particular string
 * @param str: string to be checked
 * @return VALID, INVALID
 */
int is_valid_wildcard_exist(char *str) {
	assert(str != NULL);

	// If leftmost wildcard and not only containing wildcard
	if (str[0] == '*' && str[1] == '.' && strlen(str) > WILDCARD_OFFSET) {
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
