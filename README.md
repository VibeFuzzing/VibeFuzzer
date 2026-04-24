# VibeFuzzer

TODO: usage instructions

## Build instructions

There is an all-in-one setup script that has been tested to work on Ubuntu. To run it, use the following cURL command:

`curl -fsSL https://raw.githubusercontent.com/VibeFuzzing/VibeFuzzer/refs/heads/main/setup.sh | sudo sh`

The following are manual setup instructions, particularly for non-Ubuntu distros:

### Dependencies

This program requires `libcjson-dev` and `libcurl-dev` of some variety for the custom mutator code itself. It also requires Ollama for running the LLM.

### Builidng and installing the model

1. Enter into `model` and run `./fetch_and_merge.sh`; this will grab the model file from the repository.
2. Still in the `model` directory, run `ollama create afl-mutator -f Modelfile`

### Building the mutator

Make sure you have the source directory of the AFL++ version you're intending to use in an accessible location.

Then, in the `mutator` directory, run `AFL_PATH=/path/to/AFLplusplus make` to build the mutator.
