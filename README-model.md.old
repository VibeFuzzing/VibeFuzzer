# AFL++ Seed Mutator

Fine-tuned Llama 3.1 8B model for generating AFL++ seed mutations. Trained on ancestry chains from fuzzing nginx.

## Setup

### 1. Install Ollama
Download from [ollama.com](https://ollama.com)

### 2. Clone this repo
```
git clone https://github.com/VibeFuzzing/llm-mutator.git
cd llm-mutator
```

### 3. Download model parts
Download all 3 model parts from the [Releases page](https://github.com/VibeFuzzing/llm-mutator/releases):
- `model_q4km.part0`
- `model_q4km.part1`
- `model_q4km.part2`

Place them in the repo directory.

### 4. Reassemble the model

**Windows (PowerShell):**
```
.\reassemble_gguf.ps1 model_q4km.gguf
```

**Linux/Mac:**
```
chmod +x reassemble_gguf.sh
./reassemble_gguf.sh model_q4km.gguf
```

### 5. Create the Ollama model
```
ollama create afl-mutator -f Modelfile
```

## Usage

```
ollama run afl-mutator
```

Provide an ancestry chain of seeds with metadata:

```
[id:0 depth:1 bitmap:406 favored:False new_cov:True]
GET / HTTP/1.1\r\n\r\n
---
[id:1 depth:2 bitmap:435 favored:True new_cov:True]
GET / HTTP/1.1\r
---
[id:67 depth:2 bitmap:432 favored:True new_cov:False]
GEP /\xfdGwT11/:\xb8TT:/12G/\x04
```

The model outputs a mutated seed that can be fed to AFL++.

## How It Works

The model was trained on seed mutation lineages extracted from AFL++ fuzzing campaigns. Each training example contains an ancestry chain showing how seeds evolved through mutations, paired with a successful child seed that discovered new coverage or was favored by AFL++. The model learns to produce the next productive mutation given a history of prior seeds.
