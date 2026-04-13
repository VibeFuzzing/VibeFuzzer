#include "ollama.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

// Ollama must be running: ollama run <model-name>

static void init_curl_response(struct CurlResponse *r) {
    r->len = 0;
    r->str = malloc(1);
    if (r->str) {
        r->str[0] = '\0';
    }
}

static size_t curl_writefn(void *data, size_t size, size_t nmemb, void *userp) {
    size_t tot = size * nmemb;
    struct CurlResponse *s = userp;
    char *newp = realloc(s->str, s->len + tot + 1);
    if (!newp)          /* OOM – signal error by returning 0 */
        return 0;
    s->str = newp;
    memcpy(s->str + s->len, data, tot);
    s->len += tot;
    s->str[s->len] = '\0';
    return tot;
}

char *http_request(const char *method, const char *url, const char *body) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        return NULL;
    }

    struct CurlResponse resp;
    init_curl_response(&resp);

    curl_easy_setopt(curl, CURLOPT_URL, url);

    if (method && *method) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    }
    if (body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        /* optionally set length explicitly:
           curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body)); */
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        free(resp.str);
        return NULL;
    }
    return resp.str;        /* caller must free() */
}

void init_generate_data(OllamaGenerateResponse *r) {
    r->str = NULL;
    r->str_len = 0;
    r->arr = NULL;
    r->arr_len = 0;
}

void free_generate_data(OllamaGenerateResponse *r) {
    free(r->str);
    free(r->arr);
    free(r);
}

void generate_append_string(OllamaGenerateResponse *r, const char *src) {
    size_t add_len = strlen(src);
    size_t new_len = r->str_len + add_len;

    char *tmp = realloc(r->str, new_len + 1);
    if (!tmp) return;

    memcpy(tmp + r->str_len, src, add_len + 1);  // includes null terminator

    r->str = tmp;
    r->str_len = new_len;
}

int generate_set_long_array(OllamaGenerateResponse *r, const long *src, size_t count) {
    long *tmp = NULL;

    if (count > 0) {
        tmp = malloc(count * sizeof(long));
        if (!tmp) return 0;

        memcpy(tmp, src, count * sizeof(long));
    }

    free(r->arr);

    r->arr = tmp;
    r->arr_len = count;
    return 1;
}

cJSON *create_long_array(const long *values, int length) {
    cJSON *array = cJSON_CreateArray();
    if (!array) return NULL;

    for (int i = 0; i < length; i++) {
        cJSON_AddItemToArray(array, cJSON_CreateNumber(values[i]));
    }
    return array;
}

long *cjson_to_long_array(const cJSON *json_arr, size_t *out_len) {
    if (!cJSON_IsArray(json_arr)) {
        *out_len = 0;
        return NULL;
    }

    size_t count = cJSON_GetArraySize(json_arr);
    long *arr = NULL;

    if (count > 0) {
        arr = malloc(count * sizeof(long));
        if (!arr) {
            *out_len = 0;
            return NULL;
        }

        for (size_t i = 0; i < count; i++) {
            const cJSON *item = cJSON_GetArrayItem(json_arr, i);
            if (!cJSON_IsNumber(item)) {
                free(arr);
                *out_len = 0;
                return NULL;
            }
            arr[i] = (long)item->valuedouble;  // cJSON stores numbers as double
        }
    }

    *out_len = count;
    return arr;
}

OllamaGenerateResponse *ollama_generate(const char *base_url, const char *model, const char *prompt, const long *context_arr, size_t context_len)
{
    if (!base_url || !model || !prompt) {
        fprintf(stderr, "Invalid input parameters\n");
        return NULL;
    }

    /* construct JSON payload */
    cJSON *root = cJSON_CreateObject();
    if (!root)
        return NULL;
    cJSON_AddStringToObject(root, "model", model);
    cJSON_AddStringToObject(root, "prompt", prompt);
    if (context_arr && context_len > 0) {
        cJSON_AddItemToObject(root, "context", create_long_array(context_arr, context_len));
    }

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        return NULL;
    }

    /* build full URL */
    size_t len = strlen(base_url) + strlen("/api/generate") + 1;
    char *url = malloc(len);
    if (!url) {
        free(body);
        return NULL;
    }
    strcpy(url, base_url);
    strcat(url, "/api/generate");

    char *resp = http_request("POST", url, body);
    free(body);
    free(url);

    if (!resp) {
        printf("generate failed\n");
        return NULL;
    }

    /* process response */
    OllamaGenerateResponse *data = malloc(sizeof(OllamaGenerateResponse));
    if (!data) {
        free(resp);
        return NULL;
    }
    init_generate_data(data);


    char *words = strtok(resp, "\r\n");
    while (words) {
        cJSON *json = cJSON_Parse(words);
        if (!json) {
            words = strtok(NULL, "\r\n");
            continue;  /* skip invalid JSON lines */

        }

        cJSON *response = cJSON_GetObjectItem(json, "response");
        cJSON *done = cJSON_GetObjectItem(json, "done");

        if (!response || !done) {
            cJSON_Delete(json);
            words = strtok(NULL, "\r\n");
            continue;  /* skip if expected fields are missing */
        }

        generate_append_string(data, response->valuestring);

        if (done && done->valueint) {
            cJSON *done_reason = cJSON_GetObjectItem(json, "done_reason");
            if (done_reason && strcmp(done_reason->valuestring, "stop") != 0) {
                fprintf(stderr, "Warning: done_reason is '%s', expected 'stop'\n", done_reason->valuestring);
                return NULL;
            }
            
            cJSON *context = cJSON_GetObjectItem(json, "context");
            size_t context_len = 0;
            long *ctx = cjson_to_long_array(context, &context_len);

            generate_set_long_array(data, ctx, context_len); 
        }

        cJSON_Delete(json);
        words = strtok(NULL, "\r\n");
    }
    free(resp);

    return data;
}

void init_chat_message(OllamaChatMessage *msg) {
    msg->str = NULL;
    msg->str_len = 0;
    msg->role = NULL;
    msg->role_len = 0;
}

void chat_append_string(OllamaChatMessage *msg, const char *str) {
    size_t add_len = strlen(str);
    size_t new_len = msg->str_len + add_len;

    char *tmp = realloc(msg->str, new_len + 1);
    if (!tmp) {
        return;
    }

    memcpy(tmp + msg->str_len, str, add_len + 1);  // includes null terminator

    msg->str = tmp;
    msg->str_len = new_len;
}

void chat_set_role(OllamaChatMessage *msg, const char *role) {
    size_t role_len = strlen(role);

    char *tmp = realloc(msg->role, role_len + 1);
    if (!tmp) {
        return;
    }

    memcpy(tmp, role, role_len + 1);  // includes null terminator

    msg->role = tmp;
    msg->role_len = role_len;
}

void init_chat_history(OllamaChatHistory *history) {
    history->messages = NULL;
    history->msg_count = 0;
}

void free_chat_history(OllamaChatHistory *history) {
    if (history->messages) {
        for (size_t i = 0; i < history->msg_count; i++) {
            free(history->messages[i].str);
            free(history->messages[i].role);
        }
        free(history->messages);
    }
    free(history);
}

void history_add_message(OllamaChatHistory *history, OllamaChatMessage *msg) {
    OllamaChatMessage *tmp = realloc(history->messages, (history->msg_count + 1) * sizeof(OllamaChatMessage));
    if (!tmp) {
        return;
    }

    history->messages = tmp;
    history->messages[history->msg_count] = *msg;  // copy message struct
    history->msg_count++;
}

void print_chat_history(const OllamaChatHistory *history) {
    for (size_t i = 0; i < history->msg_count; i++) {
        printf("[%s]: %s\n", history->messages[i].role, history->messages[i].str);
    }
}

OllamaChatMessage *ollama_chat(const char *base_url, const char *model, const char *role, const char *prompt, OllamaChatHistory *history) {
    if (strcmp(role, "user") != 0 && strcmp(role, "system") != 0) {
        fprintf(stderr, "Invalid role: %s. Must be 'user' or 'system'.\n", role);
        return NULL;
    }

    /* construct JSON payload */
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        fprintf(stderr, "Failed to create JSON root object\n");
        return NULL;
    }
    cJSON_AddStringToObject(root, "model", model);

    // add new message to the end of the history array
    OllamaChatMessage *chat_data = malloc(sizeof(OllamaChatMessage));
    if (!chat_data) {
        cJSON_Delete(root);
        fprintf(stderr, "Failed to allocate memory for chat data\n");
        return NULL;
    }
    init_chat_message(chat_data);
    chat_append_string(chat_data, prompt);
    chat_set_role(chat_data, role);
    history_add_message(history, chat_data);  // add new message to history

    /* build messages array from history */
    cJSON *messages = cJSON_CreateArray();
    if (!messages) {
        cJSON_Delete(root);
        fprintf(stderr, "Failed to create JSON messages array\n");
        return NULL;
    }
    for (size_t i = 0; i < history->msg_count; i++) {
        cJSON *msg_obj = cJSON_CreateObject();
        if (!msg_obj) {
            cJSON_Delete(root);
            fprintf(stderr, "Failed to create JSON message object\n");
            return NULL;
        }
        cJSON_AddStringToObject(msg_obj, "role", history->messages[i].role);
        cJSON_AddStringToObject(msg_obj, "content", history->messages[i].str);
        cJSON_AddItemToArray(messages, msg_obj);
    }

    // add new message to the end of the array
    cJSON_AddItemToObject(root, "messages", messages);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        return NULL;
    }

    /* build full URL */
    size_t len = strlen(base_url) + strlen("/api/chat") + 1;
    char *url = malloc(len);
    if (!url) {
        free(body);
        return NULL;
    }
    strcpy(url, base_url);
    strcat(url, "/api/chat");

    char *resp = http_request("POST", url, body);
    free(body);
    free(url);

    if (!resp) {
        printf("chat failed\n");
        return NULL;
    }

    OllamaChatMessage *response_chat = malloc(sizeof(OllamaChatMessage));
    if (!response_chat) {
        free(resp);
        return NULL;
    }
    init_chat_message(response_chat);

    /* process response */
    char *lines = strtok(resp, "\r\n");
    while (lines) {
        cJSON *json = cJSON_Parse(lines);
        if (!json) {
            lines = strtok(NULL, "\r\n");
            continue;  /* skip invalid JSON lines */
        }

        cJSON *message = cJSON_GetObjectItem(json, "message");
        if (message) {
            cJSON *content = cJSON_GetObjectItem(message, "content");
            chat_append_string(response_chat, content->valuestring);
        }

        cJSON *done = cJSON_GetObjectItem(json, "done");
        if (done && done->valueint) {
            cJSON *done_reason = cJSON_GetObjectItem(json, "done_reason");
            cJSON *role = cJSON_GetObjectItem(message, "role");
            chat_set_role(response_chat, role->valuestring);
            if (done_reason && strcmp(done_reason->valuestring, "stop") != 0) {
                fprintf(stderr, "Warning: done_reason is '%s', expected 'stop'\n", done_reason->valuestring);
                free(response_chat);
                return NULL;
            }
        }

        cJSON_Delete(json);
        lines = strtok(NULL, "\r\n");
    }
    free(resp);
    history_add_message(history, response_chat);  // add response to history

    return response_chat;
}
