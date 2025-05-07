use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use csv::Writer;

#[derive(Debug, Default)]
struct UnsafeStats {
    raw_pointers: usize,
    ffi: usize,
    concurrency: usize,
    unsafe_fns: usize,
    other: usize,
    high_risk: usize,
}

#[derive(Debug)]
struct CodeFinding {
    file: String,
    line: usize,
    pattern: String,
    risk: String,
    suggestion: String,
}

fn detect_risk(line: &str) -> (&'static str, &'static str, &'static str) {
    let line = line.trim();

    if line.contains("*const") || line.contains("*mut") {
        let risk = if line.contains("get_unchecked") || line.contains("offset") {
            "HIGH: Pointer arithmetic without bounds check"
        } else {
            "MEDIUM: Raw pointer usage"
        };
        return ("raw_pointers", risk, "Consider using NonNull<T>");
    }

    if line.contains("extern \"C\"") || line.contains("libc::") {
        let risk = if !line.contains("// SAFETY:") {
            "HIGH: FFI without safety comment"
        } else {
            "MEDIUM: FFI with documentation"
        };
        return ("ffi", risk, "Add SAFETY comment");
    }

    if line.contains("static mut") {
        return ("concurrency", "HIGH: Mutable static variable", "Use Atomic types or thread_local!");
    }

    if line.contains("unsafe impl Send") || line.contains("unsafe impl Sync") {
        return ("concurrency", "HIGH: Manual Send/Sync impl", "Verify thread safety");
    }

    if line.contains("mem::transmute") {
        return ("mem::transmute", "HIGH: mem::transmute used", "Avoid unless absolutely necessary");
    }

    if line.contains("asm!") || line.contains("llvm_asm!") {
        return ("asm", "HIGH: Inline assembly used", "Use with extreme care and safety comment");
    }

    if line.contains("ptr::read") || line.contains("ptr::write") {
        return ("ptr::read/write", "HIGH: Manual pointer read/write", "Use safe abstractions if possible");
    }

    if line.contains("Box::from_raw") || line.contains("Vec::from_raw_parts") {
        return ("from_raw_parts", "HIGH: Creating from raw parts", "Ensure proper ownership and layout");
    }

    if line.contains("Drop::drop(") {
        return ("Drop::drop", "HIGH: Manual call to Drop::drop()", "Never call drop() manually");
    }

    if line.contains("MaybeUninit::assume_init") {
        return ("assume_init", "HIGH: Unsafe uninitialized memory access", "Ensure initialization before use");
    }

    if line.contains("mem::zeroed()") {
        return ("mem::zeroed", "HIGH: mem::zeroed() can lead to undefined behavior", "Avoid unless you know what you're doing");
    }

    ("other", "LOW", "Review for potential safety issues")
}

fn scan_file(path: &Path) -> (UnsafeStats, Vec<CodeFinding>, HashMap<String, usize>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", path.display(), e);
            return (UnsafeStats::default(), vec![], HashMap::new());
        }
    };

    let mut stats = UnsafeStats::default();
    let mut findings = vec![];
    let mut pattern_counts = HashMap::new();
    let mut in_unsafe_block = false;
    let mut unsafe_depth = 0;

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("unsafe {") {
            in_unsafe_block = true;
            unsafe_depth += 1;
        }

        if in_unsafe_block || trimmed.starts_with("unsafe") || trimmed.contains("unsafe ") {
            let (pattern, risk, suggestion) = detect_risk(line);

            match pattern {
                "raw_pointers" => stats.raw_pointers += 1,
                "ffi" => stats.ffi += 1,
                "concurrency" => stats.concurrency += 1,
                "unsafe_fns" => stats.unsafe_fns += 1,
                _ => stats.other += 1,
            }

            if risk.starts_with("HIGH") {
                stats.high_risk += 1;
            }

            *pattern_counts.entry(pattern.to_string()).or_insert(0) += 1;

            findings.push(CodeFinding {
                file: path.display().to_string(),
                line: line_num + 1,
                pattern: pattern.to_string(),
                risk: risk.to_string(),
                suggestion: suggestion.to_string(),
            });
        }

        if trimmed.contains('}') && in_unsafe_block {
            unsafe_depth -= 1;
            if unsafe_depth == 0 {
                in_unsafe_block = false;
            }
        }
    }

    (stats, findings, pattern_counts)
}

fn walk_dir(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walk_dir(&path));
            } else if path.extension().map_or(false, |ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        println!("Usage: cargo run -- <path-to-rust-project>");
        std::process::exit(1);
    });

    let dir = Path::new(&path);
    if !dir.exists() {
        eprintln!("Error: Path '{}' does not exist", dir.display());
        std::process::exit(1);
    }

    let files = walk_dir(dir);
    let total_files = files.len();

    if total_files == 0 {
        println!("No Rust files found in {}", dir.display());
        return Ok(());
    }

    let project_name = dir.file_name()
        .and_then(|os_str| os_str.to_str())
        .unwrap_or("project");

    let report_filename = format!("{}_unsafe_report.csv", project_name);
    let mut wtr = Writer::from_path(&report_filename)?;
    wtr.write_record(&["File", "Line", "Pattern", "Risk Level", "Suggestion"])?;

    let mut total_stats = UnsafeStats::default();
    let mut global_pattern_counts = HashMap::<String, usize>::new();

    for file in &files {
        let (stats, findings, pattern_counts) = scan_file(file);

        if !findings.is_empty() {
            for finding in findings {
                wtr.write_record(&[
                    &finding.file,
                    &finding.line.to_string(),
                    &finding.pattern,
                    &finding.risk,
                    &finding.suggestion,
                ])?;
            }
        }

        total_stats.raw_pointers += stats.raw_pointers;
        total_stats.ffi += stats.ffi;
        total_stats.concurrency += stats.concurrency;
        total_stats.unsafe_fns += stats.unsafe_fns;
        total_stats.other += stats.other;
        total_stats.high_risk += stats.high_risk;

        for (pattern, count) in pattern_counts {
            *global_pattern_counts.entry(pattern).or_insert(0) += count;
        }
    }

    wtr.flush()?;

    // Pattern summary CSV
    let summary_filename = format!("{}_pattern_summary.csv", project_name);
    let mut summary_writer = Writer::from_path(&summary_filename)?;
    summary_writer.write_record(&["Pattern", "Count"])?;
    for (pattern, count) in &global_pattern_counts {
        summary_writer.write_record(&[pattern, &count.to_string()])?;
    }
    summary_writer.flush()?;

    // Console Output
    println!("\n=== Summary ===");
    println!("Total files scanned: {}", total_files);
    println!("Total unsafe patterns detected:");
    println!("- Raw pointers: {}", total_stats.raw_pointers);
    println!("- FFI: {}", total_stats.ffi);
    println!("- Concurrency: {}", total_stats.concurrency);
    println!("- Unsafe functions: {}", total_stats.unsafe_fns);
    println!("- Other: {}", total_stats.other);
    println!("- High-risk patterns: {}", total_stats.high_risk);

    println!("\n=== Detailed Pattern Breakdown ===");
    for (pattern, count) in &global_pattern_counts {
        println!("- {}: {}", pattern, count);
    }

    println!("\nReports generated:");
    println!("- {}", report_filename);
    println!("- {}", summary_filename);

    Ok(())
}
