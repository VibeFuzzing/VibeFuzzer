#!/bin/bash
# reassemble_gguf.sh
# Usage: ./reassemble_gguf.sh model_q4km.gguf
# Looks for model_q4km.part0, model_q4km.part1, etc. in current directory

OUTPUT="$1"
BASENAME="${OUTPUT%.*}"

if [ -z "$OUTPUT" ]; then
    echo "Usage: ./reassemble_gguf.sh model_q4km.gguf"
    exit 1
fi

echo "Reassembling parts into $OUTPUT..."

# Clear output file
> "$OUTPUT"

# Concatenate parts in numeric order
PART=0
while [ -f "${BASENAME}.part${PART}" ]; do
    echo "  Reading ${BASENAME}.part${PART}..."
    cat "${BASENAME}.part${PART}" >> "$OUTPUT"
    PART=$((PART + 1))
done

if [ "$PART" -eq 0 ]; then
    echo "Error: No part files found matching ${BASENAME}.part*"
    rm -f "$OUTPUT"
    exit 1
fi

echo "Done! Reassembled $PART parts into $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"