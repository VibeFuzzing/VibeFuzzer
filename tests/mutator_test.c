#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "afl-fuzz.h"
#include "types.h"
#include "test_utils.h"
#include "../mutator/ollama.h"

/**
 * @brief  Test the helper functions for chat messages and history, including initialization, string appending, role setting, and history management. This verifies that the OllamaChatMessage and OllamaChatHistory structures are correctly updated and that memory is managed properly.
 * 
 */
typedef struct llm_mutator {
    afl_state_t *afl;
    const char *base_url;
    const char *model;
    OllamaChatHistory *history;
    FILE *log_file;
} llm_mutator_t;

/**
 * @brief  Test the afl_custom_init function to ensure that it correctly initializes the llm_mutator_t structure with the expected values from environment variables and sets up the HEX_TO_DIGIT mapping. This verifies that the mutator is properly configured for use in fuzzing.
 * 
 */
typedef struct string {
    char *data;
    size_t len;
    size_t cap;
} string_t;

/**
 * @brief  Create a new growable string.
 * @return The initialized string.
 */
string_t new_string(void);

/**
 * @brief  Free the memory allocated for a growable string.
 * 
 * @param self  The string to free.
 */
void free_string(string_t *self);

/**
 * @brief  Append a single character to the growable string, resizing if necessary.
 * 
 * @param self  The string to append to.
 * @param ch  The character to append.
 */
void string_push(string_t *self, char ch);

/**
 * @brief  Append a null-terminated string to the growable string, resizing if necessary.
 * 
 * @param self  The string to append to.
 * @param string  The null-terminated string to append.
 */
void string_push_str(string_t *self, const char *string);

/**
 * @brief  Custom fuzzing function for AFL that uses the Ollama API to generate mutated inputs based on the provided chat history and model. This function reads the input from a file, sends it to the Ollama API, processes the response, and produces a new mutated input for fuzzing.
 * 
 * @param afl  A pointer to the AFL state structure.
 * @param seed  A random seed for initialization.
 * @return llm_mutator_t*  A pointer to the initialized mutator data structure.
 */
llm_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed);

/**
 * @brief  Custom fuzzing function for AFL that uses the Ollama API to generate mutated inputs based on the provided chat history and model. This function reads the input from a file, sends it to the Ollama API, processes the response, and produces a new mutated input for fuzzing.
 * 
 * @param data  A pointer to the mutator data structure initialized by afl_custom_init.
 * @param buf  A pointer to the input buffer (not used in this implementation, as input is read from a file).
 * @param buf_size  The size of the input buffer (not used in this implementation).
 * @param out_buf  A pointer to a pointer where the output buffer will be stored (the caller is responsible for freeing this buffer).
 * @param add_buf  A pointer to an additional input buffer (not used in this implementation).
 * @param add_buf_size  The size of the additional input buffer (not used in this implementation).
 * @param max_size  The maximum size of the output buffer to produce.
 * @return size_t  The size of the output buffer produced, or 0 on failure.
 */
size_t afl_custom_fuzz(llm_mutator_t *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size);

/**
 * @brief  Custom deinitialization function for AFL that frees the resources allocated for the mutator data structure. This should be called when the fuzzing session is complete to clean up any allocated memory and close any open files.
 * 
 * @param data  A pointer to the mutator data structure to deinitialize and free.
 */
void afl_custom_deinit(llm_mutator_t *data);

extern uint8_t HEX_TO_DIGIT[256];

/**
 * @brief  Test the string helper functions for creating and managing a growable string. This verifies that the new_string function initializes the string correctly, that string_push and string_push_str correctly append characters and strings while resizing as needed, and that free_string properly frees the allocated memory.
 * 
 */
static void test_string_helpers(void) {
    string_t s = new_string();
    assert(s.data != NULL);
    assert(s.len == 1);
    assert(s.cap == 1);
    assert(s.data[0] == '\0');

    string_push(&s, 'A');
    assert(s.len == 2);
    assert(s.data[1] == 'A');

    string_push_str(&s, "BC");
    assert(s.len == 4);
    assert(memcmp(s.data + 1, "ABC", 3) == 0);

    string_push_str(&s, "");
    assert(s.len == 4);

    free_string(&s);
}

/**
 * @brief  Test the afl_custom_init function to ensure that it correctly initializes the llm_mutator_t structure with the expected values from environment variables and sets up the HEX_TO_DIGIT mapping. This verifies that the mutator is properly configured for use in fuzzing.
 * 
 */
static void test_afl_custom_init(void) {
    setenv("OLLAMA_URL", "http://localhost:11434", 1);
    setenv("OLLAMA_MODEL", "test-model", 1);

    afl_state_t afl = {0};
    llm_mutator_t *data = afl_custom_init(&afl, 42);
    assert(data != NULL);
    assert(data->base_url != NULL);
    assert(strcmp(data->base_url, "http://localhost:11434") == 0);
    assert(strcmp(data->model, "test-model") == 0);
    assert(data->history != NULL);
    assert(data->history->msg_count == 0);
    assert(data->log_file != NULL);
    assert(HEX_TO_DIGIT['0'] == 0);
    assert(HEX_TO_DIGIT['a'] == 10);
    assert(HEX_TO_DIGIT['F'] == 15);

    afl_custom_deinit(data);
    remove("llm-mutator-log.txt");
}

/**
 * @brief  Test the afl_custom_fuzz function to verify that it correctly reads input from a file, sends a request to the Ollama API, processes the response, and produces the expected mutated output. This test uses a mock HTTP request to simulate the Ollama API response and checks that the output buffer contains the expected data based on the mock response.
 * 
 */
static void test_afl_custom_fuzz(void) {
    setenv("OLLAMA_URL", "http://localhost:11434", 1);
    setenv("OLLAMA_MODEL", "test-model", 1);
    reset_http_mock();

    set_http_mock_expectations(
        "POST",
        "http://localhost:11434/api/chat",
        "\"messages\"",
        "{\"message\": {\"role\": \"assistant\", \"content\": \"hello\"}, \"done\": 1, \"done_reason\": \"stop\"}"
    );

    char template[] = "/tmp/mutator_test.XXXXXX";
    int fd = mkstemp(template);
    assert(fd >= 0);

    const char payload[] = "A\nB\tC";
    ssize_t written = write(fd, payload, sizeof(payload) - 1);
    assert(written == (ssize_t)(sizeof(payload) - 1));
    close(fd);

    struct queue_entry entry = {
        .id = 1,
        .depth = 0,
        .bitmap_size = 8,
        .favored = false,
        .has_new_cov = false,
        .fname = template,
    };
    struct queue_entry *queue_buf[1] = {&entry};
    afl_state_t afl = {.queued_items = 1, .queue_buf = queue_buf};

    llm_mutator_t *data = afl_custom_init(&afl, 42);
    assert(data != NULL);

    uint8_t *out_buf = NULL;
    size_t out_len = 0;
    
    // The mutator only calls the API every 200 iterations, so we need to call it 200 times
    // to get the API result. This loop simulates what happens during fuzzing.
    for (int i = 0; i < 200; i++) {
        free(out_buf);
        out_buf = NULL;
        out_len = afl_custom_fuzz(data, NULL, 0, &out_buf, NULL, 0, 128);
    }
    
    // Verify we got the LLM response on the 200th call
    assert(out_len == 6);
    assert(out_buf != NULL);
    assert(out_buf[0] == 0);
    assert(memcmp(out_buf + 1, "hello", 5) == 0);
    assert(get_http_request_calls() == 1);

    free(out_buf);
    afl_custom_deinit(data);
    unlink(template);
    remove("llm-mutator-log.txt");
}

/**
 * @brief  Test the afl_custom_deinit function to ensure that it properly frees the resources allocated for the mutator data structure. This verifies that memory is freed and files are closed without leaks or errors.
 * 
 * @return int  Returns 0 on success, or a non-zero value if the test fails.
 */
int main(void) {
    run_test("string_helpers", test_string_helpers);
    run_test("afl_custom_init", test_afl_custom_init);
    run_test("afl_custom_fuzz", test_afl_custom_fuzz);
    printf("All mutator tests passed.\n");
    return 0;
}
