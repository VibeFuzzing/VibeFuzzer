#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stddef.h>

/**
 * @brief  Utility functions and mock implementations for testing the mutator and Ollama integration. This includes functions for managing growable strings, mocking HTTP requests, and running test cases with assertions. These utilities are used across multiple test files to verify the correctness of the mutator's behavior and its interaction with the Ollama API.
 * 
 */
void reset_http_mock(void);

/**
 * @brief Set the http mock expectations object 
 * 
 * @param method  The expected HTTP method (e.g., "POST").
 * @param url  The expected URL (e.g., "http://localhost:11434/api/chat").
 * @param body_substring  A substring that should be present in the request body (can be NULL if not checking).
 * @param response_body  The response body to return when the mock HTTP request function is called (can be NULL to return no response).
 */
void set_http_mock_expectations(const char *method,
                                const char *url,
                                const char *body_substring,
                                const char *response_body);

/**
 * @brief Get the http request calls object
 * 
 * @return int  The number of times the mock HTTP request function has been called.
 */
int get_http_request_calls(void);

/**
 * @brief  Run a test function and print the test name and result. This function takes the name of the test and a pointer to the test function to execute. It prints the name of the test being run, calls the test function, and then prints a success message if the test passes without any assertions failing. If an assertion fails within the test function, it will cause the test to fail and print an error message indicating which assertion failed.
 *  
 * @param name  The name of the test being run (for logging purposes).
 * @param test_fn  A pointer to the test function to execute. The test function should contain assertions to verify the expected behavior of the code under test.
 */
void run_test(const char *name, void (*test_fn)(void));

#endif // TEST_UTILS_H
