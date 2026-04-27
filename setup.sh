currentdir=`pwd`

SUDO_SCRIPT=$(mktemp) && {

cat > $SUDO_SCRIPT << "EOF"
apt-get update
apt-get install \
    git curl tmux \
    automake cargo cmake meson ninja-build \
    bison build-essential clang flex lld llvm llvm-dev \
    python3-dev python3-setuptools python3-venv \
    libcjson-dev libcurl4-openssl-dev libglib2.0-dev libpixman-1-dev libgtk-3-dev

GCC_VERSION=$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')
apt-get install gcc-$GCC_VERSION-plugin-dev libstdc++-$GCC_VERSION-dev
EOF
  
echo Installing packages with apt-get. This step requires root.

sudo sh $SUDO_SCRIPT

rm -f $SUDO_SCRIPT

} || echo Unable to verify required packages are installed

curl -fsSL https://ollama.com/install.sh | sh

rm -rf ~/.vibe-fuzzer
mkdir ~/.vibe-fuzzer
cd ~/.vibe-fuzzer

mkdir .venv
python3 -m venv .venv
. .venv/bin/activate

mkdir bin
cd bin
cat > vibe-fuzz << "EOF"

source ~/.vibe-fuzzer/.venv/bin/activate
python3 ~/.vibe-fuzzer/VibeFuzzer/vibefuzzer.py $@ && tmux attach -t vibefuzzer

EOF
chmod +x vibe-fuzz
cd ..

echo "export PATH=$PATH:$HOME/.vibe-fuzzer/bin" >> ~/.bashrc

git clone https://www.github.com/VibeFuzzing/VibeFuzzer
cd VibeFuzzer
pip install -r requirements.txt

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
