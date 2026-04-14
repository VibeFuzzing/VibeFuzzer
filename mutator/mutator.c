#include "afl-fuzz.h"
#include "ollama.h"
#include "types.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct llm_mutator {
  afl_state_t *afl;
  const char *base_url;
  const char *model;
  OllamaChatHistory *history;
  FILE *log_file;
} llm_mutator_t;

uint8_t HEX_TO_DIGIT[256];

/**
 * @brief  Custom initialization function for AFL that sets up the mutator data structure with the expected values from environment variables and initializes the HEX_TO_DIGIT mapping. This should be called at the start of the fuzzing session to prepare the mutator for use.
 * 
 * @param afl  A pointer to the AFL state structure, which contains information about the fuzzing queue and other state.
 * @param seed  A seed value for randomization (not used in this implementation but can be used for future enhancements).
 * @return llm_mutator_t*  A pointer to the initialized mutator data structure, or NULL on failure.
 */
llm_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  srand(seed);

  llm_mutator_t *data = calloc(1, sizeof(llm_mutator_t));

  data->afl = afl;
  data->base_url = getenv("OLLAMA_URL");
  data->model = getenv("OLLAMA_MODEL");
  data->history = calloc(1, sizeof(OllamaChatHistory));
  init_chat_history(data->history);
  data->log_file = fopen("llm-mutator-log.txt", "wb");

  HEX_TO_DIGIT['0'] = 0;
  HEX_TO_DIGIT['1'] = 1;
  HEX_TO_DIGIT['2'] = 2;
  HEX_TO_DIGIT['3'] = 3;
  HEX_TO_DIGIT['4'] = 4;
  HEX_TO_DIGIT['5'] = 5;
  HEX_TO_DIGIT['6'] = 6;
  HEX_TO_DIGIT['7'] = 7;
  HEX_TO_DIGIT['8'] = 8;
  HEX_TO_DIGIT['9'] = 9;

  HEX_TO_DIGIT['a'] = 10;
  HEX_TO_DIGIT['b'] = 11;
  HEX_TO_DIGIT['c'] = 12;
  HEX_TO_DIGIT['d'] = 13;
  HEX_TO_DIGIT['e'] = 14;
  HEX_TO_DIGIT['f'] = 15;

  HEX_TO_DIGIT['A'] = 10;
  HEX_TO_DIGIT['B'] = 11;
  HEX_TO_DIGIT['C'] = 12;
  HEX_TO_DIGIT['D'] = 13;
  HEX_TO_DIGIT['E'] = 14;
  HEX_TO_DIGIT['F'] = 15;

  return data;
}

/** 
 * @brief  growable string helper
 * 
 */
typedef struct string {
  char *data;
  size_t len;
  size_t cap;
} string_t;

/**
 * @brief  Create a new growable string with initial capacity. The string is initialized to be empty (length 0) but has a null terminator at the start of the data buffer. The caller is responsible for freeing the memory allocated for the string using free_string when it is no longer needed.
 * 
 * @return string_t  A new string_t structure representing the growable string.
 */
string_t new_string() {
  string_t result;
  result.data = calloc(1, 1);
  result.len = 1;
  result.cap = 1;

  return result;
}

/**
 * @brief  Free the memory allocated for a growable string. This function should be called when the string is no longer needed to avoid memory leaks. It frees the data buffer and resets the length and capacity to 0.
 * 
 * @param self  The string to free.
 */
void free_string(string_t *self) { free(self->data); }

/** 
 * @brief  Ensure that the growable string has at least the specified minimum capacity. If the current capacity is less than the required minimum, the function will double the capacity until it meets or exceeds the minimum. The data buffer is reallocated as needed to accommodate the new capacity. This function is used internally by string_push and string_push_str to ensure there is enough space for new characters or strings being appended.
 * 
 */
void string_resize(string_t *self, size_t new_min_cap) {
  bool needs_realloc = 0;
  while (new_min_cap > self->cap) {
    needs_realloc = 1;
    size_t new_cap = MAX(16, self->cap * 2);
    self->cap = new_cap;
  }
  if (needs_realloc) {
    self->data = realloc(self->data, self->cap);
  }
}

/**
 * @brief  Append a single character to the growable string, resizing if necessary. This function ensures that there is enough capacity in the string to accommodate the new character, and then appends it to the end of the string, updating the length accordingly. The string remains null-terminated after the new character is added.
 * 
 * @param self  The string to append to.
 * @param ch  The character to append.
 */
void string_push(string_t *self, char ch) {
  string_resize(self, self->len + 1);
  self->data[self->len] = ch;
  self->len += 1;
}

/**
 * @brief  Append a null-terminated string to the growable string, resizing if necessary. This function calculates the length of the string to append, ensures that there is enough capacity in the growable string to accommodate the new characters, and then appends the new string to the end of the growable string, updating the length accordingly. The growable string remains null-terminated after the new string is added.
 * 
 * @param self  The string to append to.
 * @param string  The null-terminated string to append.
 */
void string_push_str(string_t *self, const char *string) {
  size_t add_len = strlen(string);
  if (add_len == 0) {
    return;
  }
  string_resize(self, self->len + add_len);
  memcpy(self->data + self->len, string, add_len);
  self->len += add_len;
}

char NUM_TO_HEX[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

/**
 * @brief  Custom fuzzing function for AFL that uses the Ollama API to generate mutated inputs based on the provided chat history and model. This function reads the input from a file, sends it to the Ollama API, processes the response, and produces a new mutated input for fuzzing. The function handles escaping of special characters in the input and output, and logs any errors encountered during processing.
 * 
 * @param data  A pointer to the mutator data structure initialized by afl_custom_init, which contains the AFL state, base URL, model, chat history, and log file.
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
                       size_t max_size) {
  string_t input_buf = new_string();
  char temp[256] = {0}; // Temporary storage buffer (oversized intentionally)

  bool need_sep = 0;
  for (int i = 0; i < data->afl->queued_items; ++i) {
    if (need_sep) {
      string_push_str(&input_buf, "--\n");
    }
    need_sep = 1;

    struct queue_entry *entry = data->afl->queue_buf[i];
    snprintf(temp, 256, "[id:%d depth:%llu bitmap:%d favored:%s new_cov:%s]\n",
             entry->id, entry->depth, entry->bitmap_size,
             entry->favored ? "True" : "False",
             entry->has_new_cov ? "True" : "False");

    string_push_str(&input_buf, temp);

    // Read seed from disk
    FILE *seed_file = fopen((const char *)entry->fname, "rb");

    fseek(seed_file, 0, SEEK_END);
    size_t seed_len = ftell(seed_file);
    fseek(seed_file, 0, SEEK_SET);

    char *seed_buf = malloc(seed_len);
    fread(seed_buf, 1, seed_len, seed_file);

    for (int j = 0; j < seed_len; ++j) {
      char cur_ch = seed_buf[j];
      if (cur_ch >= 32 && cur_ch <= 126)
        string_push(&input_buf, cur_ch);
      else if (cur_ch == '\t')
        string_push_str(&input_buf, "\\t");
      else if (cur_ch == '\n')
        string_push_str(&input_buf, "\\n");
      else if (cur_ch == '\r')
        string_push_str(&input_buf, "\\r");
      else {
        char escaped[4] = {'\\', NUM_TO_HEX[cur_ch >> 4],
                           NUM_TO_HEX[cur_ch & 0xf], 0};
        string_push_str(&input_buf, escaped);
      }
    }

    free(seed_buf);
    fclose(seed_file);

    string_push(&input_buf, '\n');
  }

  OllamaChatMessage *response;
  while (!(response = ollama_chat(data->base_url, data->model, "user",
                                  input_buf.data, data->history))) {
    fprintf(data->log_file, "error occurred in chat, retrying...\n");
  }

  free_string(&input_buf);

  string_t output_builder = new_string();

  if (response->str[0] == '_' && response->str[1] == '_' &&
      response->str[2] == 'b' && response->str[3] == '6' &&
      response->str[4] == '4' && response->str[5] == '_' &&
      response->str[6] == '_') {
    fprintf(data->log_file,
            "detected base64 request from LLM. This is currently "
            "unimplemented.\nraw LLM response:\n%s\n",
            response->str);
  } else {
    for (int i = 0; i < response->str_len; ++i) {
      if (response->str[i] == '\\') {
        i += 1;
        if (response->str[i] == 'x') {
          // TODO: error handling if we get e.g. \x#l
          string_push(&output_builder,
                      (HEX_TO_DIGIT[response->str[i + 1]] << 4) |
                          (HEX_TO_DIGIT[response->str[i + 2]]));
          i += 2;
        } else if (response->str[i] == 'n') {
          string_push(&output_builder, '\n');
        } else if (response->str[i] == 'r') {
          string_push(&output_builder, '\r');
        } else if (response->str[i] == 't') {
          string_push(&output_builder, '\t');
        } else {
          // PANIC
          fprintf(data->log_file,
                  "encountered unexpected escape \"\\%c\" in LLM response\nraw "
                  "LLM response:\n%s\n",
                  response->str[i], response->str);
        }
      } else {
        string_push(&output_builder, response->str[i]);
      }
    }
  }

  *out_buf = (uint8_t *)output_builder.data;
  // leak output_builder's buffer
  return output_builder.len;
}

// TODO: free more things.
void afl_custom_deinit(llm_mutator_t *data) { free(data); }
