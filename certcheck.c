/**
 * Main C files for TLS certificate check (COMP30023) - Project 2
 * Author: Maleakhi Agung Wijaya (maleakhiw)
 * Date: 21/05/2018
 */

#include "certvalidation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/******************************************************************************/
/** Constant */

#define DEFAULT_SIZE 2000
#define ARG_COUNT 2
#define FILE_PATH_INDEX 1
#define OUTPUT_FILE "output.csv"

/******************************************************************************/
/** Function Declaration*/

/*
 * Used to read a line in csv file which also handle realloc buffer size
 * @param input_fp: Input file pointer
 * @return buffer: the string buffer
 */
char *read_line(FILE *input_fp);

/******************************************************************************/
/** Main Function */

int main(int argc, char *argv[]) {
    char *csv_file = NULL, *line = NULL, *certificate_name = NULL, *host_name = NULL;
    FILE *input_fp = NULL, *output_fp = NULL;
    int is_valid;

    /* Initialise (opening file check command line argument) & read csv */
    if (argc != ARG_COUNT) {
        fprintf(stderr, "Please use the correct format: ./certcheck [pathToTestFile]\n");
        exit(EXIT_FAILURE);
    }
    // Read file name
    csv_file = argv[FILE_PATH_INDEX];

    // Read CSV from the specified file name
    // Opening file for reading and writing
    input_fp = fopen(csv_file, "r");
    output_fp = fopen(OUTPUT_FILE, "w+");
    if ((input_fp == NULL) || (output_fp == NULL)) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    // Read from input file and output to output file
    while ((line = read_line(input_fp)) != NULL) {
        // Process the line and separate certificate name and host name
        get_certificate_host_name(line, &certificate_name, &host_name);

        /* Process full validation of certificate */
        is_valid = full_certificate_validation(certificate_name, host_name);

        // Write to output file
        fputs(line, output_fp);
        fprintf(output_fp, ",%d\n", is_valid);

        // Defensive style free
        free(line);
        free(certificate_name);
        free(host_name);
        line = NULL;
        certificate_name = NULL;
        host_name = NULL;
    }

    // Close file
    fclose(input_fp);
    fclose(output_fp);

    return 0;
}

/******************************************************************************/
/** Other Functions */

/*
 * Used to read a line in csv file which also handle realloc buffer size
 * @param input_fp: Input file pointer
 * @return buffer: the string buffer
 */
char *read_line(FILE *input_fp) {
    int size = DEFAULT_SIZE, ch, position = 0;
    char *buffer = (char *) malloc(sizeof(char) * size);
    assert(buffer != NULL);

    // Read input per one character until a new line or EOF
    while ((ch = fgetc(input_fp)) != '\n' && ch != EOF && !feof(input_fp)) {
        buffer[position++] = ch;

        // Check if needed more memory because buffer size cannot accommodate
        if (position == size) {
            size *= 2; // increase the size by 2 times (geometric increase)
            buffer = (char *) realloc(buffer, size);
            assert(buffer != NULL);
        }
        buffer[position] = '\0'; // nullbyte
    }

    // Indication of EOF, return NULL
    if (position == 0) {
        free(buffer); // buffer are not used, free it
        return NULL;
    }

    return buffer;
}
