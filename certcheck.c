/**
 * Author: Maleakhi Agung Wijaya
 * Date: 19/05/2018
 * Computer Systems (COMP30023) Project 2
 */

 /*****************************LIBRARY&CONSTANT********************************/
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/******************************FUNCTION*DECLARATION***************************/

int is_certificate_date_valid(ASN1_TIME *not_before, ASN1_TIME *not_after);

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
    ASN1_TIME *not_before = NULL;
    ASN1_TIME *not_after = NULL;
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
    not_before = X509_get_notBefore(cert);
    not_after = X509_get_notAfter(cert);

    int validity = is_certificate_date_valid(not_before, not_after);
    printf("The certificates is %d\n", validity);

    /************* Testing Minimum Key Length ****************/

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
 * @param not_before: indicate not_before date
 * @param not_after: indicate not_after date
 * @return 0: invalid date range, 1: valid date range
 */
int is_certificate_date_valid(ASN1_TIME *not_before, ASN1_TIME *not_after) {
	int day, sec;
	ASN1_TIME *today = NULL;

	// Current date should be between the not before and not after date
	// Check not_before first with today's date, immediately return 0 (invalid)
	// if today's date is before not_before date
	if (!ASN1_TIME_diff(&day, &sec, not_before, today)) {
		fprintf(stderr, "Invalid time format.");
		exit(EXIT_FAILURE);
	}

	// If today's date is before not_before date
	if (day < 0 || sec < 0) {
		return 0; // invalid
	}

	// Check not_after date with today's date, today's date should be before
	// not_after date
	if (!ASN1_TIME_diff(&day, &sec, today, not_after)) {
		fprintf(stderr, "Invalid time format.");
		exit(EXIT_FAILURE);
	}

	// If not_after date is before today's date
	if (day < 0 || sec < 0) {
		return 0; // invalid
	}

	return 1; // it is valid if within range
}
