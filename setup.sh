currentdir=`pwd`

sudo apt-get update
sudo apt-get install -y git curl python3-venv meson libcjson-dev libcurl4-openssl-dev tmux

sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# sudo apt-get install -y lld-14 llvm-14 llvm-14-dev clang-14 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo apt-get install -y ninja-build # for QEMU mode

curl -fsSL https://ollama.com/install.sh | sh

rm -rf ~/.vibe-fuzzer
mkdir ~/.vibe-fuzzer
cd ~/.vibe-fuzzer

mkdir .venv
python3 -m venv .venv
. .venv/bin/activate
pip3 install ollama

mkdir bin
cd bin
cat > vibe-fuzz << "EOF"

source ~/.vibe-fuzzer/.venv/bin/activate
python3 ~/.vibe-fuzzer/VibeFuzzer/afl++wrapper.py $@ && tmux attach -t vibefuzzer

EOF
chmod +x vibe-fuzz
cd ..

echo "export PATH=$PATH:$HOME/.vibe-fuzzer/bin" >> ~/.bashrc

git clone https://www.github.com/VibeFuzzing/VibeFuzzer
cd VibeFuzzer

git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install
cd ..

git clone https://github.com/fkie-cad/libdesock
cd libdesock
meson setup ./build && cd ./build && meson compile

cd ../../model
./fetch_and_merge.sh
ollama create afl-mutator -f Modelfile

cd ../mutator
AFL_PATH=../AFLplusplus make

cd $currentdir
