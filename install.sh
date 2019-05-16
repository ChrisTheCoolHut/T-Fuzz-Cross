
pip install -r n_req.txt
pip install -r n_req.txt --no-deps
pip install git+https://github.com/shellphish/fuzzer.git
pip install keystone-engine
git clone https://github.com/shellphish/shellphish-afl.git
echo "export PATH=$PATH:$(pwd)/shellphish-afl/bin/afl-unix/" >> ~/.bashrc
pip install r2pipe
echo core | sudo tee /proc/sys/kernel/core_pattern
echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first
