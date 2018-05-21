/**
 * C file used to captures the function declaration of certificate Validation
 * logic for COMP30023 (Computer Systems) Project 2 - TLS Certificate Checking
 * Author: Maleakhi Agung Wijaya
 * Date: 21/05/2018
 */

#include "certvalidation.h"

/******************************************************************************/
/** Constant */

#define MAX_DOMAIN_NAME 256 // standard maximum domain name char size
#define WILDCARD_POSITION 0 // the position of '*' in valid wild card
#define DOT_POSITION 1 // the position of '.' in valid wild card
#define WILDCARD_OFFSET 2
#define VALID 1
#define INVALID 0
#define BITS_CONVERSION 8 // conversion bytes -> bits
#define MINIMUM_KEY_LENGTH 2048
#define EXTENDED_KEY_AUTH "TLS Web Server Authentication"
#define NAME_BUFFER_LENGTH 1024

/******************************************************************************/
/** Certificate Validation Function */

/*
 * Used to separate line string (CSV format) into two array
 * @param line: string which we will be separating
 * @param certificate_name: pointer of certificate name to be filled
 * @param host_name: pointer of host name to be filled
 */
void get_certificate_host_name(char *line, char **certificate_name, char **host_name) {
    char *delimiter_csv = ",", *delimiter_new_line = "\n", *token;

    // As strtok will break string, create a new string for line
    char *new_line = (char *) malloc(sizeof(char) * (strlen(line)+1));
    assert(new_line != NULL);
    strcpy(new_line, line);

    // Tokenize line
    token = strtok(new_line, delimiter_csv);
    *certificate_name = (char *) malloc(sizeof(char) * (strlen(line)+1));
    assert(certificate_name != NULL);
    strcpy(*certificate_name, token);

    token = strtok(NULL, delimiter_new_line);
    *host_name = (char *) malloc(sizeof(char) * (strlen(line)+1));
    assert(host_name != NULL);
    strcpy(*host_name, token);

    free(new_line);
}

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

	/* Process to get SAN */
	san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

	/** Validity check */
	// If san names not null, will process san names in addition to common name
	if (san_names != NULL) {
        // Create and fill san_array
        char **san_array = NULL;
        length_san_array = fill_san_array(san_names, &san_array);
		sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

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
    assert(*san_array != NULL);
    // Iterate and fill the SAN array
    for (i=0; i<san_names_count; i++) {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

        if (current_name->type == GEN_DNS) {
            // Copy san name to san array
            char *dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);
            (*san_array)[i] = (char *) malloc(sizeof(char) * (strlen(dns_name)+1)); // extra nullbyte
            assert((*san_array)[i] != NULL);
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
    EVP_PKEY_free(public_key);
    
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
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID, -1));
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
    assert(*value_buffer != NULL);
    memcpy(*value_buffer, bptr->data, bptr->length);
    (*value_buffer)[bptr->length] = '\0';

    // Free the bio
    BIO_free_all(bio);
}

/**
 * Used to aggregate full validation check on the certificate
 * @param certificate_name: string where the certificate is located
 * @param host_name: string for the host name (second column in csv)
 * @return VALID, INVALID
 */
int full_certificate_validation(char *certificate_name, char *host_name) {
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    int is_valid_date, is_valid_domain, is_valid_length, is_valid_usage;

    /* Initialise open ssl and bio certificate */
    // Initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // Create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    // Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, certificate_name))) {
        fprintf(stderr, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }
    // Read into cert which contains the X509 certificate and can be used to analyse the certificate
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
        fprintf(stderr, "Error in loading certificate\n");
        exit(EXIT_FAILURE);
    }

    /* Testing validation of dates */
    // Read not before and not after date
    is_valid_date = is_certificate_date_valid(cert);

    /* Domain name validation (CN & SAN) */
    is_valid_domain = is_domain_name_valid(cert, host_name);

    /* RSA key length validation */
    is_valid_length = is_key_length_valid(cert);

    /* Correct key usage validation (Basic Constraint & Extended Key Usage) */
    is_valid_usage = (is_ca_false_valid(cert) && is_extended_key_usage_valid(cert));

    X509_free(cert);
    BIO_free_all(certificate_bio);

    return (is_valid_date && is_valid_domain && is_valid_length && is_valid_usage);
}
