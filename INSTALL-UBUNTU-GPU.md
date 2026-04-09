# Ubuntu GPU Setup (RunPod / Cloud)

Setup instructions for running benchmarks on a fresh Ubuntu GPU machine.

## CUDA 12.8

```bash
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
```

```bash
dpkg -i cuda-keyring_1.1-1_all.deb
```

```bash
apt-get update && apt-get install -y cuda-toolkit-12-8
```

```bash
echo 'export PATH=/usr/local/cuda-12.8/bin:$PATH' >> ~/.bashrc
```

```bash
echo 'export CUDA_PATH=/usr/local/cuda-12.8' >> ~/.bashrc
```

```bash
ln -sf /usr/local/cuda-12.8 /usr/local/cuda
```

```bash
source ~/.bashrc
```

## System deps

```bash
apt-get install -y pkg-config libssl-dev cmake protobuf-compiler git
```

## Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

```bash
source ~/.bashrc
```

## RISC Zero

```bash
curl -L https://risczero.com/install | bash
```

```bash
source ~/.bashrc
```

```bash
rzup install
```

## Clone and build

```bash
git clone https://github.com/remix7531/slh-dsa-stark-bench.git
```

```bash
cd slh-dsa-stark-bench
```

```bash
cargo build --release --features cuda
```

## Run benchmarks

```bash
bash demo/run.sh 1
```
