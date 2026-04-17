#!/bin/bash

rm -rf tmp
mkdir tmp
pushd tmp

for url in $(python ../fetch_model_urls.py)
do
    curl $url -LO
done

../reassemble_gguf.sh model_q4km.gguf

popd

mv tmp/model_q4km.gguf .
rm -rf tmp
