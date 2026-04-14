#include <cjson/cJSON.h> /* requires libcjson-dev or the header in include path */
#include <stddef.h>
#include <stdlib.h>

#define OLLAMA_URL "http://localhost:11434"
#define MODEL_NAME "llama3"


// -- GENERATE API --

/**
 * struct for holding API responses and context
 */
typedef struct {
  char *str;      // dynamically allocated string
  size_t str_len; // number of characters (not counting null terminator)

  long *arr;      // dynamically allocated int array
  size_t arr_len; // number of integers
} OllamaGenerateResponse;

/**
 * @brief Initialize an OllamaGenerateResponse structure
 * 
 * @param r OllamaGenerateResponse to initialize
 */
void init_generate_data(OllamaGenerateResponse *r);

/**
 * @brief Free the memory allocated for an OllamaGenerateResponse structure
 * 
 * @param r OllamaGenerateResponse to free
 */
void free_generate_data(OllamaGenerateResponse *r);

/**
 * @brief Append a string to an OllamaGenerateResponse structure
 * 
 * @param r OllamaGenerateResponse to append to
 * @param src String to append (must be null-terminated)
 */
void generate_append_string(OllamaGenerateResponse *r, const char *src);

/**
 * @brief Set the long array in an OllamaGenerateResponse structure
 * 
 * @param d OllamaGenerateResponse to update
 * @param src Source long array to copy from
 * @param count Number of elements in the source array
 * @return int 1 on success, 0 on failure
 */
int generate_set_long_array(OllamaGenerateResponse *r, const long *src, size_t count);

/**
 * @brief Convert long array to cJSON object
 * 
 * @param values array of long values to convert
 * @param length length of the values array
 * @return cJSON* a cJSON array object, or NULL on failure (caller must free)
 */
cJSON *create_long_array(const long *values, int length);

/**
 * @brief Convert a cJSON array to a long array
 * 
 * @param json_arr The cJSON array to convert
 * @param out_len Pointer to store the length of the resulting array
 * @return long* The resulting long array, or NULL on error
 */
long *cjson_to_long_array(const cJSON *json_arr, size_t *out_len);


// -- CHAT API --

/*
 * build a JSON body for /api/generate and perform the request.
 *
 * @param base_url  e.g. "http://localhost:11434" (no trailing slash)
 * @param model     model name ("llama3", etc.)
 * @param prompt    prompt text
 * @return          malloc'd response string or NULL on failure; caller frees
 */
OllamaGenerateResponse *ollama_generate(const char *base_url, const char *model, const char *prompt, const long *context_arr, size_t context_len);

typedef struct {
  char *str;      // dynamically allocated string
  size_t str_len; // number of characters (not counting null terminator)

  char *role;
  size_t role_len;
} OllamaChatMessage;

/**
 * @brief Initialize an OllamaChatMessage structure
 * 
 * @param msg OllamaChatMessage to initialize
 */
void init_chat_message(OllamaChatMessage *msg);

/**
 * @brief Append a string to an OllamaChatMessage's content, reallocating as needed.
 * 
 * @param msg OllamaChatMessage to append to
 * @param str String to append (must be null-terminated)
 */
void chat_append_string(OllamaChatMessage *msg, const char *str);

/**
 * @brief Set the role of an OllamaChatMessage.
 *
 * @param msg OllamaChatMessage to set the role for
 * @param role The role to set (must be null-terminated)
 */
void chat_set_role(OllamaChatMessage *msg, const char *role);

/**
 * @brief Structure to hold the chat history
 */
typedef struct {
  OllamaChatMessage *messages; // dynamically allocated array of messages
  size_t msg_count;            // number of messages in the array
} OllamaChatHistory;

/**
 * @brief Initialize an OllamaChatHistory structure
 * 
 * @param history OllamaChatHistory to initialize
 */
void init_chat_history(OllamaChatHistory *history);

/**
 * @brief Free the memory allocated for an OllamaChatHistory structure
 * 
 * @param history OllamaChatHistory to free
 */
void free_chat_history(OllamaChatHistory *history);

/**
 * @brief Add a message to the chat history.
 * 
 * @param history OllamaChatHistory to add the message to
 * @param msg OllamaChatMessage to add
 */
void history_add_message(OllamaChatHistory *history, OllamaChatMessage *msg);

/**
 * @brief Print the chat history (for debugging purposes)
 * 
 * @param history OllamaChatHistory to print
 */
void print_chat_history(const OllamaChatHistory *history);

/**
 * @brief Send a chat message to the Ollama API
 * 
 * @param base_url The base URL of the Ollama API
 * @param model The model to use
 * @param role The role of the message sender ("user" or "system")
 * @param prompt The message content
 * @param history OllamaChatHistory containing the conversation history (will be updated with the new message and response)
 * @return OllamaChatMessage* The response OllamaChatMessage or NULL on failure
 */
OllamaChatMessage *ollama_chat(const char *base_url, const char *model, const char *role, const char *prompt, OllamaChatHistory *history);

void set_http_request_fn(char *(*fn)(const char *, const char *, const char *));


// -- helper functions for HTTP requests and response handling --

/**
 * @brief Structure to hold the HTTP response
 */
struct CurlResponse {
    char *str;
    size_t len;
};

/**
 * @brief Write function for libcurl
 * 
 * @param data Data received from the server
 * @param size Size of each element in the data array
 * @param nmemb Number of elements in the data array
 * @param userp User pointer (points to CurlResponse structure)
 * @return size_t Number of bytes written
 */
