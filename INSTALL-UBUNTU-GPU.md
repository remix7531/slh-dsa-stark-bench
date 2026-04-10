# Ubuntu GPU Setup

Alternative to the Nix flake for running on cloud GPU machines (RunPod, Lambda Labs, etc).

## Dependencies + CUDA 12.8

```bash
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
```

```bash
dpkg -i cuda-keyring_1.1-1_all.deb
```

```bash
apt-get update && apt-get install -y pkg-config libssl-dev cmake protobuf-compiler git libclang-dev cuda-toolkit-12-8
```

```bash
echo 'export PATH=/usr/local/cuda-12.8/bin:$PATH
export CUDA_PATH=/usr/local/cuda-12.8' >> ~/.bashrc
```

```bash
ln -sf /usr/local/cuda-12.8 /usr/local/cuda
```

```bash
source ~/.bashrc
```

## Rust + RISC Zero

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

```bash
source ~/.bashrc
```

```bash
curl -L https://risczero.com/install | bash
```

```bash
source ~/.bashrc
```

```bash
rzup install
```

## Build and run

```bash
git clone https://github.com/remix7531/slh-dsa-stark-bench.git
```

```bash
cd slh-dsa-stark-bench
```

```bash
cargo build --release --features cuda
```

```bash
bash demo/run.sh 1
```

## Tuning segment size

Larger segments reduce recursion overhead but need more VRAM. Default is PO2=20 (~1M cycles per segment), maximum is PO2=24. Override with `RISC0_SEGMENT_PO2`:

```bash
RISC0_SEGMENT_PO2=22 bash demo/run.sh 1
```
