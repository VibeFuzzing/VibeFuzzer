#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../mutator/ollama.h"
#include "test_utils.h"

/**
 * @brief  Test the helper functions for OllamaGenerateResponse, including initialization, string appending, and long array setting. This verifies that the structure is correctly updated and memory is managed properly.
 * 
 */
static void test_generate_helpers(void) {
    OllamaGenerateResponse *r = malloc(sizeof(*r));
    assert(r != NULL);
    init_generate_data(r);
    assert(r->str == NULL);
    assert(r->str_len == 0);
    assert(r->arr == NULL);
    assert(r->arr_len == 0);

    generate_append_string(r, "Hello");
    assert(r->str_len == 5);
    assert(strcmp(r->str, "Hello") == 0);

    generate_append_string(r, " world");
    assert(r->str_len == 11);
    assert(strcmp(r->str, "Hello world") == 0);

    long values[] = {10, 20, 30};
    assert(generate_set_long_array(r, values, 3) == 1);
    assert(r->arr_len == 3);
    assert(r->arr[0] == 10);
    assert(r->arr[1] == 20);
    assert(r->arr[2] == 30);

    assert(generate_set_long_array(r, NULL, 0) == 1);
    assert(r->arr_len == 0);
    assert(r->arr == NULL);

    free_generate_data(r);
}

/**
 * @brief  Test the conversion of long arrays to cJSON arrays and back. This verifies that the create_long_array function correctly builds a cJSON array from a C array, and that cjson_to_long_array correctly parses a cJSON array back into a C array, including handling of invalid input.
 * 
 */
static void test_json_array_roundtrip(void) {
    long values[] = {1, 2, 3, 4};
    cJSON *array = create_long_array(values, 4);
    assert(array != NULL);
    assert(cJSON_IsArray(array));
    assert(cJSON_GetArraySize(array) == 4);

    size_t out_len = 0;
    long *copied = cjson_to_long_array(array, &out_len);
    assert(copied != NULL);
    assert(out_len == 4);
    assert(copied[0] == 1);
    assert(copied[3] == 4);

    free(copied);
    cJSON_Delete(array);

    cJSON *bad = cJSON_CreateObject();
    assert(bad != NULL);
    size_t bad_len = 0;
    long *bad_result = cjson_to_long_array(bad, &bad_len);
    assert(bad_result == NULL);
    assert(bad_len == 0);
    cJSON_Delete(bad);
}

/**
 * @brief  Test the ollama_generate function using a mock HTTP request. This verifies that the function correctly constructs the request, handles the response, and populates the OllamaGenerateResponse structure with the expected string and long array data based on the mock response.
 * 
 */
static void test_ollama_generate_mock(void) {
    reset_http_mock();
    set_http_mock_expectations(
        "POST",
        "http://localhost:11434/api/generate",
        "\"model\":\"test-model\"",
        "{\"response\":\"Hello\",\"done\":0}\r\n{\"response\":\" world\",\"done\":1,\"done_reason\":\"stop\",\"context\": [1,2,3]}"
    );

    long context[] = {1, 2, 3};
    OllamaGenerateResponse *result = ollama_generate("http://localhost:11434", "test-model", "This is a prompt", context, 3);
    assert(result != NULL);
    assert(result->str_len == 11);
    assert(strcmp(result->str, "Hello world") == 0);
    assert(result->arr_len == 3);
    assert(result->arr[0] == 1);
    assert(result->arr[1] == 2);
    assert(result->arr[2] == 3);
    assert(get_http_request_calls() == 1);

    free_generate_data(result);
}

/**
 * @brief  Test the ollama_generate function with invalid input parameters. This verifies that the function correctly handles NULL pointers for base_url, model, and prompt, and that it does not make any HTTP requests when given invalid input.
 * 
 */
static void test_ollama_generate_invalid_input(void) {
    reset_http_mock();
    assert(ollama_generate(NULL, "m", "p", NULL, 0) == NULL);
    assert(ollama_generate("http://localhost:11434", NULL, "p", NULL, 0) == NULL);
    assert(ollama_generate("http://localhost:11434", "m", NULL, NULL, 0) == NULL);
    assert(get_http_request_calls() == 0);
}

/**
 * @brief  Test the helper functions for chat messages and history, including initialization, string appending, role setting, and history management. This verifies that the OllamaChatMessage and OllamaChatHistory structures are correctly updated and that memory is managed properly.
 * 
 */
static void test_chat_helpers_and_history(void) {
    OllamaChatMessage msg;
    init_chat_message(&msg);
    chat_append_string(&msg, "Hello");
    chat_set_role(&msg, "user");
    assert(strcmp(msg.str, "Hello") == 0);
    assert(strcmp(msg.role, "user") == 0);

    OllamaChatHistory *history = malloc(sizeof(*history));
    assert(history != NULL);
    init_chat_history(history);
    history_add_message(history, &msg);
    assert(history->msg_count == 1);
    assert(strcmp(history->messages[0].str, "Hello") == 0);
    assert(strcmp(history->messages[0].role, "user") == 0);

    free_chat_history(history);
}

/**
 * @brief  Test the ollama_chat function using a mock HTTP request. This verifies that the function correctly constructs the chat request, processes the response, updates the chat history, and returns the expected chat message based on the mock response.
 * 
 */
static void test_ollama_chat_mock(void) {
    reset_http_mock();
    set_http_mock_expectations(
        "POST",
        "http://localhost:11434/api/chat",
        "\"messages\"",
        "{\"message\": {\"role\": \"assistant\", \"content\": \"Hello from bot\"}, \"done\": 1, \"done_reason\": \"stop\"}"
    );

    OllamaChatHistory *history = malloc(sizeof(*history));
    assert(history != NULL);
    init_chat_history(history);

    OllamaChatMessage *response = ollama_chat("http://localhost:11434", "chat-model", "user", "Hi there", history);
    assert(response != NULL);
    assert(strcmp(response->str, "Hello from bot") == 0);
    assert(strcmp(response->role, "assistant") == 0);
    assert(history->msg_count == 2);
    assert(strcmp(history->messages[0].role, "user") == 0);
    assert(strcmp(history->messages[1].role, "assistant") == 0);
    assert(strcmp(history->messages[1].str, "Hello from bot") == 0);
    assert(get_http_request_calls() == 1);

    free(response->str);
    free(response->role);
    free(response);
    free_chat_history(history);
}

/**
 * @brief  Test the ollama_chat function with an invalid role in the request. This verifies that the function correctly handles an invalid role by returning NULL and not adding any messages to the chat history.
 * 
 */
static void test_ollama_chat_invalid_role(void) {
    reset_http_mock();
    OllamaChatHistory *history = malloc(sizeof(*history));
    assert(history != NULL);
    init_chat_history(history);

    assert(ollama_chat("http://localhost:11434", "chat-model", "invalid-role", "Hi there", history) == NULL);
    assert(history->msg_count == 0);
    free_chat_history(history);
}

/**
 * @brief  Main function to run all tests for the Ollama integration. This function calls each test function in turn and prints the results. If all assertions pass, it will print "All tests passed." at the end.
 * 
 * @return int  Exit code (0 for success)
 */
int main(void) {
    run_test("generate_helpers", test_generate_helpers);
    run_test("json_array_roundtrip", test_json_array_roundtrip);
    run_test("ollama_generate_mock", test_ollama_generate_mock);
    run_test("ollama_generate_invalid_input", test_ollama_generate_invalid_input);
    run_test("chat_helpers_and_history", test_chat_helpers_and_history);
    run_test("ollama_chat_mock", test_ollama_chat_mock);
    run_test("ollama_chat_invalid_role", test_ollama_chat_invalid_role);

    printf("All tests passed.\n");
    return 0;
}
