Python script for Wireguard Post-Quantum PSK Key Exchange

### Configure, build and install liboqs

sudo apt -y install libssl-dev

Execute in a Terminal/Console/Administrator Command Prompt

```shell
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel 8
cmake --build liboqs/build --target install
```

### Configure and install the wrapper

Execute in a Terminal/Console/Administrator Command Prompt

```shell
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
```

### Update ldconfig

Execute in a Terminal/Console/Administrator Command Prompt

```shell
rm /etc/ld.so.cache
ldconfig
```

## Finishing touch

Remove warnings from /usr/local/lib/python3.10/dist-packages/oqs/oqs.py
