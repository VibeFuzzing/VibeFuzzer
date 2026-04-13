# Example Usage
```
void main() {
    // Generate API message
    OllamaGenerateResponse *data = ollama_generate(OLLAMA_URL, MODEL_NAME, "Respond with blue next time I talk to you", NULL, 0);
    printf("Full response:\n%s\n", data->str);
    free_generate_data(&data);

    // Chat API message (with existing chat history)
    OllamaChatHistory history;
    init_chat_history(&history);

    OllamaChatMessage *msg1 = malloc(sizeof(OllamaChatMessage));
    init_chat_message(msg1);
    chat_append_string(msg1, "Respond with blue next time I talk to you");
    chat_set_role(msg1, "system");
    history_add_message(&history, msg1);

    OllamaChatMessage *data = ollama_chat(OLLAMA_URL, MODEL_NAME, "user", "Hello", &history);
    print_chat_history(&history);
    free_chat_history(&history);
}
```