
mkvirtualenv TFuzz -p /usr/bin/python3
git clone https://github.com/radare/radare2.git

# Uncomment deb-src in apt list
sudo sed -i 's/# deb-src/deb-src/g' /etc/apt/sources.list

# Get required files from apt
sudo apt update -y
sudo apt-get install build-essential gcc-multilib libtool automake autoconf bison debootstrap debian-archive-keyring -y
sudo apt-get build-dep qemu-system -y
sudo apt-get install libacl1-dev -y
sudo apt install cmake -y

# Make radare2
cd radare2
./sys/install.sh
cd ..

# Make pip packages
pip install git+https://github.com/ChrisTheCoolHut/shellphish-afl
pip install git+https://github.com/ChrisTheCoolHut/fuzzer
pip install git+https://github.com/angr/tracer
pip install -r n_req.txt
pip install keystone-engine

# Install keystone in a virtualenv will not place libkeystone correctly
# Place it into a library folder than get's searched
sudo cp $(find $VIRTUAL_ENV -iname libkeystone.so) /lib/

#echo "export PATH=$PATH:$(pwd)/shellphish-afl/bin/afl-unix/" >> ~/.bashrc
echo core | sudo tee /proc/sys/kernel/core_pattern
echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first
