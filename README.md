# Computer Systems Project 2 - TLS Certificate Checker

## About  
A simple Certificate TLS checker written in C. Here is a list of checking that
the checker do:  
1. Validation of dates, both the *Not Before* and *Not After* dates
2. Domain name validation (Common Name and Subject Alternative Names)
3. Minimum key length of 2048 bits for RSA
4. Correct key usage, including extension

## Guide
- Just type `make` in the terminal where the file are and the Makefile will automatically build the server for you
- To test the server the command is: `./certcheck [pathToTestFile]`
- To clean the executable, just type `make clean`

## File Structure
- Input file will be a CSV file with first column a certificate file path and second column as host name
- Output file will be 'output.csv' with first column a certificate file path, second
column as host name, and third is validity (1 for valid, 0 for invalid)
- *certvalidation.c* contains the function logic of the certificate checker
- *certvalidation.h* contains header files of *certvalidation.c*
- *certcheck.c* is the main file responsible for reading csv and calling certificate
validation

## Author Details
**Name**: Maleakhi Agung Wijaya (maleakhiw)  
**Student ID**: 784091
