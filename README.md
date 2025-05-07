# Unsafe Patterns Scanner in Rust

This project scans Rust source code for potentially unsafe patterns and generates CSV reports with detailed findings.

### Crates Scanned:
- regex
- tokio
- hyper
- rayon
- mio

### Output Files:
- `<crate>_unsafe_report.csv`: Detailed findings per line of code.
- `<crate>_pattern_summary.csv`: Summary of detected patterns and their counts.

### How to Run:
1. Clone the repository: `git clone <repository-link>`
2. Navigate to the project directory: `cd unsafe-scanner`
3. Run the scanner: `cargo run -- <path-to-rust-project>`
