#!/usr/bin/env python3
"""Plot SLH-DSA STARK signature aggregation benchmarks from CSV files.

Usage: python3 plot.py <output.svg> <csv1> [csv2] ...

Each CSV must have columns: n,prove_s,proof_kib,direct_verify_ms,stark_verify_ms
"""

import csv
import sys
from pathlib import Path

import matplotlib
matplotlib.use('svg')
import matplotlib.pyplot as plt

SIG_BYTES = 7856  # SLH-DSA-SHA2-128s

# Color cycle for multiple datasets
COLORS = ['#e74c3c', '#3498db', '#2ecc71', '#9b59b6', '#f39c12', '#1abc9c']


def label_from_filename(path: Path) -> str:
    """bench-nvidia-rtx-5090.csv -> NVIDIA RTX 5090
       bench-amd-ryzen5-8540u.csv -> AMD Ryzen 5 8540U"""
    name = path.stem.replace('bench-', '').replace('bench2-', '')
    parts = name.split('-')
    if parts[0] == 'nvidia':
        return 'NVIDIA ' + ' '.join(p.upper() for p in parts[1:])
    if parts[0] == 'amd':
        out = ['AMD']
        for p in parts[1:]:
            if p.startswith('ryzen') and len(p) > 5 and p[5:].isdigit():
                out.append(f'Ryzen {p[5:]}')
            else:
                out.append(p.upper())
        return ' '.join(out)
    return name


def load_csv(path: Path) -> list[dict]:
    with path.open() as f:
        return [{
            'n': int(r['n']),
            'prove_s': float(r['prove_s']),
            'proof_kib': float(r['proof_kib']),
            'direct_verify_ms': float(r['direct_verify_ms']),
            'stark_verify_ms': float(r['stark_verify_ms']),
        } for r in csv.DictReader(f)]


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    output = Path(sys.argv[1])
    datasets = [(label_from_filename(Path(p)), load_csv(Path(p))) for p in sys.argv[2:]]

    # Union of all N values across all datasets
    all_ns = sorted({r['n'] for _, rows in datasets for r in rows})

    fig, axes = plt.subplots(3, 1, figsize=(9, 14))
    fig.suptitle('SLH-DSA-SHA2-128s STARK Signature Aggregation\n(RISC Zero zkVM, succinct proof)',
                 fontsize=13, fontweight='bold')

    # Plot 1: prove time vs N
    ax = axes[0]
    for i, (label, rows) in enumerate(datasets):
        ns = [r['n'] for r in rows]
        ts = [r['prove_s'] for r in rows]
        ax.plot(ns, ts, 'o-', color=COLORS[i % len(COLORS)], lw=2, ms=6, label=label)
    ax.set_xscale('log', base=2)
    ax.set_yscale('log')
    ax.set_xticks(all_ns)
    ax.set_xticklabels([str(n) for n in all_ns])
    ax.xaxis.set_minor_locator(matplotlib.ticker.NullLocator())
    ax.yaxis.set_major_formatter(matplotlib.ticker.ScalarFormatter())
    ax.set_xlabel('Signatures (N)')
    ax.set_ylabel('Prove time (seconds)')
    ax.set_title('Proof Generation Time')
    ax.legend(loc='upper left', fontsize=9)
    ax.grid(True, alpha=0.3, which='both')

    # Plot 2: verification time (direct vs STARK), using the first dataset
    # (typically the consumer machine that would do verification)
    ax = axes[1]
    first_label, first_rows = datasets[0]
    ns = [r['n'] for r in first_rows]
    direct = [r['direct_verify_ms'] for r in first_rows]
    stark = [r['stark_verify_ms'] for r in first_rows]
    ax.plot(ns, direct, 'o-', color='#e74c3c', lw=2, ms=6, label='Direct verification')
    ax.plot(ns, stark, 's-', color='#2ecc71', lw=2, ms=6, label='STARK proof verification')
    ax.set_xscale('log', base=2)
    ax.set_yscale('log')
    ax.set_xticks(all_ns)
    ax.set_xticklabels([str(n) for n in all_ns])
    ax.xaxis.set_minor_locator(matplotlib.ticker.NullLocator())
    ax.yaxis.set_major_formatter(matplotlib.ticker.ScalarFormatter())
    ax.set_xlabel('Signatures (N)')
    ax.set_ylabel('Time (ms)')
    ax.set_title(f'Verification Time ({first_label})')
    ax.legend(loc='upper left', fontsize=9)
    ax.grid(True, alpha=0.3, which='both')

    # Plot 3: proof size vs raw signature size
    ax = axes[2]
    largest = max(datasets, key=lambda d: len(d[1]))[1]
    ns = [r['n'] for r in largest]
    proof_kib = [r['proof_kib'] for r in largest]
    raw_kib = [n * SIG_BYTES / 1024 for n in ns]
    ax.plot(ns, proof_kib, '^-', color='#9b59b6', lw=2, ms=6, label='STARK proof')
    ax.plot(ns, raw_kib, 'o-', color='#e74c3c', lw=2, ms=6, label='Raw SLH-DSA signatures')
    ax.set_xscale('log', base=2)
    ax.set_yscale('log')
    ax.set_xticks(all_ns)
    ax.set_xticklabels([str(n) for n in all_ns])
    ax.xaxis.set_minor_locator(matplotlib.ticker.NullLocator())
    ax.yaxis.set_major_formatter(matplotlib.ticker.ScalarFormatter())
    ax.set_xlabel('Signatures (N)')
    ax.set_ylabel('Size (KiB)')
    ax.set_title('Proof Size vs Raw Signatures')
    ax.legend(loc='upper left', fontsize=9)
    ax.grid(True, alpha=0.3, which='both')
    ax.text(1.0, -0.12, '@remix7531', transform=ax.transAxes,
            fontsize=8, color='#888888', ha='right', va='top')

    plt.tight_layout()
    fig.savefig(output, format='svg', bbox_inches='tight')
    print(f'Saved {output}')


if __name__ == '__main__':
    main()
