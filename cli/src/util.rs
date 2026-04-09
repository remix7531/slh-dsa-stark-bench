use std::time::Duration;

pub fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

pub fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Format a path relative to the current working directory.
pub fn rel_path(path: &str) -> String {
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.into());
    match std::env::current_dir() {
        Ok(cwd) => abs
            .strip_prefix(&cwd)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| abs.display().to_string()),
        Err(_) => abs.display().to_string(),
    }
}

/// Format a Duration in human-readable form.
pub fn fmt_duration(d: Duration) -> String {
    let total_secs = d.as_secs_f64();
    if total_secs < 0.001 {
        format!("{:.0}us", d.as_micros())
    } else if total_secs < 1.0 {
        format!("{:.1}ms", total_secs * 1000.0)
    } else if total_secs < 60.0 {
        format!("{:.1}s", total_secs)
    } else if total_secs < 3600.0 {
        let mins = (total_secs / 60.0).floor() as u64;
        let secs = total_secs - (mins as f64 * 60.0);
        format!("{}m {:.0}s", mins, secs)
    } else {
        let hours = (total_secs / 3600.0).floor() as u64;
        let mins = ((total_secs - hours as f64 * 3600.0) / 60.0).floor() as u64;
        let secs = total_secs - (hours as f64 * 3600.0) - (mins as f64 * 60.0);
        format!("{}h {}m {:.0}s", hours, mins, secs)
    }
}
