#!/bin/bash

rm -rf tmp
mkdir tmp
cd tmp

for url in $(python3 ../fetch_model_urls.py)
do
    curl $url -LO
done

../reassemble_gguf.sh model_q4km.gguf

cd ..

mv tmp/model_q4km.gguf .
rm -rf tmp
