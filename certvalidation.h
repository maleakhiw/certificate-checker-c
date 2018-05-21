/**
 * Header file used to captures the function declaration of certificate Validation
 * logic for COMP30023 (Computer Systems) Project 2 - TLS Certificate Checking
 * Author: Maleakhi Agung Wijaya
 * Date: 21/05/2018
 */

#ifndef CERT_VALIDATION_H
#define CERT_VALIDATION_H

/******************************************************************************/

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

/******************************************************************************/
/** Function Declaration */

/*
 * Used to separate line string (CSV format) into two array
 * @param line: string which we will be separating
 * @param certificate_name: pointer of certificate name to be filled
 * @param host_name: pointer of host name to be filled
 */
void get_certificate_host_name(char *line, char **certificate_name, char **host_name);

/**
 * Used to check whether the certificate date is currently valid
 * @param cert: certificates
 * @return VALID, INVALID
 */
int is_certificate_date_valid(X509* cert);

/**
 * Used to check whether the domain name of the certificate is valid
 * @param cert: certificate used to extract subject SAN and subject CN
 * @param certificate_url: URL from which certificates belongs (column 2)
 * @return VALID, INVALID
 */
int is_domain_name_valid(X509 *cert, char *certificate_url);

/**
 * Used to fill san_array with san
 * @param san_names: san available in STACK_OF(GENERAL_NAME) * format
 * @param san_array: array that will be used as storage of san
 * @return length_san_array: elements filled in san_array
 */
int fill_san_array(STACK_OF(GENERAL_NAME) *san_names, char ***san_array);

/**
 * Free element used by san_array
 * @param san_array: array to be freed
 * @param length_san_array: length of filled san_array
 */
void free_san_array(char ***san_array, int length_san_array);

/**
 * Used to check whether a VALID (leftmost) wildcard exist in a particular string
 * @param str: string to be checked
 * @return VALID, INVALID
 */
int is_valid_wildcard_exist(char *str);

/**
 * Used to compare host name/ certificate_url with single name
 * @param single_name: string representing a name
 * @param host_name: string representing host name
 * @return VALID: host name == common name, INVALID: otherwise
 */
int check_single_name(char *single_name, char *host_name);

/**
 * Used to compare SAN with host name/ certificate_url
 * @param san_name: array of strings
 * @param length_san_array: length of san_array
 * @param host_name: string representing host name
 * @return VALID if host name is contain in the san name, INVALID otherwise
 */
int check_san(char **san_array, int length_san_array, char *host_name);

/**
 * Check validity of RSA key length
 * @param cert: certificate
 * @return VALID if (>= 2048 bits), INVALID otherwise
 */
int is_key_length_valid(X509 *cert);

/**
 * Used to check whether CA: FALSE
 * @param cert: certificate
 * @return VALID if CA: FALSE , otherwise INVALID
 */
int is_ca_false_valid(X509 *cert);

/**
 * Used to check whether extended key usage is valid (contain EXTENDED_KEY_AUTH)
 * @param cert: certificate
 * @return VALID if contain TLS Web Server Authentication, INVALID otherwise
 */
int is_extended_key_usage_valid(X509* cert);

/**
 * Used to get extension name and value (most of the code using Chris Culnane example)
 * @param cert: certificate
 * @param NID: nid of the extensions
 * @param extension_name_ptr: pointer to extension name that will be filled
 * @param extension_value_ptr: pointer to extension value that will be filled
 */
void ext_name_value(X509 *cert, int NID, char name_buffer[], char **value_buffer);

/**
 * Used to aggregate full validation check on the certificate
 * @param certificate_name: string where the certificate is located
 * @param host_name: string for the host name (second column in csv)
 * @return VALID, INVALID
 */
int full_certificate_validation(char *certificate_name, char *host_name);

/******************************************************************************/

#endif
