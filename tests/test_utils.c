#include "test_utils.h"
#include "../mutator/ollama.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *g_expected_method;
static const char *g_expected_url;
static const char *g_expected_body_substring;
static const char *g_response_body;
static int g_http_request_calls;

/**
 * @brief  Helper function to duplicate a string. This function allocates memory for a new string and copies the contents of the source string into it. The caller is responsible for freeing the memory allocated for the duplicated string when it is no longer needed.
 * 
 * @param src  The source string to duplicate (must be null-terminated).
 * @return char*  A pointer to the newly allocated duplicated string, or NULL if memory allocation fails.
 */
static char *duplicate_string(const char *src) {
    size_t len = strlen(src);
    char *dup = malloc(len + 1);
    if (!dup) {
        return NULL;
    }
    memcpy(dup, src, len + 1);
    return dup;
}

/**
 * @brief  Mock implementation of the HTTP request function used for testing. This function checks that the method, URL, and body of the request match the expected values set by the test, and returns a predefined response body if the expectations are met. It also counts the number of times it has been called. This allows tests to verify that the code under test is making the correct HTTP requests and handling responses as expected.
 * 
 * @param method  The HTTP method of the request (e.g., "POST").
 * @param url  The URL of the request (e.g., "http://localhost:11434/api/chat").
 * @param body  The body of the request, which should contain the expected substring if set.
 * @return char*  A pointer to the response body to return, or NULL if the expectations are not met. The caller is responsible for freeing the memory allocated for the response body when it is no longer needed.
 */
static char *mock_http_request(const char *method, const char *url, const char *body) {
    g_http_request_calls++;
    assert(method != NULL);
    assert(url != NULL);
    assert(body != NULL);
    assert(strcmp(method, g_expected_method) == 0);
    assert(strcmp(url, g_expected_url) == 0);
    if (g_expected_body_substring) {
        assert(strstr(body, g_expected_body_substring) != NULL);
    }
    if (g_response_body) {
        return duplicate_string(g_response_body);
    }
    return NULL;
}

void reset_http_mock(void) {
    set_http_request_fn(mock_http_request);
    g_expected_method = NULL;
    g_expected_url = NULL;
    g_expected_body_substring = NULL;
    g_response_body = NULL;
    g_http_request_calls = 0;
}

void set_http_mock_expectations(const char *method,
                                const char *url,
                                const char *body_substring,
                                const char *response_body) {
    g_expected_method = method;
    g_expected_url = url;
    g_expected_body_substring = body_substring;
    g_response_body = response_body;
}

int get_http_request_calls(void) {
    return g_http_request_calls;
}

void run_test(const char *name, void (*test_fn)(void)) {
    printf("[TEST] %s\n", name);
    test_fn();
    printf("[PASS] %s\n", name);
}
