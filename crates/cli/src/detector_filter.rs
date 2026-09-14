//! Shared `--only` / `--skip` filter for the detector output.
//!
//! Applied at the CLI layer (not the detector crate) so the detector
//! library stays pure + dep-free. Both flags accept a comma-separated
//! list of labels; comparison is case-insensitive and ignores spaces
//! + hyphens + underscores so users can write any of:
//!
//!   --only bootloader,kernel,init-system
//!   --only Bootloader,Kernel,"Init system"
//!   --skip network,web_admin
//!
//! Precedence: `--only` (whitelist) then `--skip` (blacklist), so
//! `--only bootloader,kernel --skip kernel` yields just Bootloader.

use bootintel_detectors::Finding;

pub fn filter(
    findings: Vec<Finding>,
    only: &Option<String>,
    skip: &Option<String>,
) -> Vec<Finding> {
    let only_set = only.as_deref().map(parse_list);
    let skip_set = skip.as_deref().map(parse_list);
    findings
        .into_iter()
        .filter(|f| {
            let key = norm(&f.label);
            if let Some(w) = &only_set {
                if !w.iter().any(|n| n == &key) {
                    return false;
                }
            }
            if let Some(b) = &skip_set {
                if b.iter().any(|n| n == &key) {
                    return false;
                }
            }
            true
        })
        .collect()
}

fn parse_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| norm(x.trim()))
        .filter(|x| !x.is_empty())
        .collect()
}

/// Normalize: lowercase, strip spaces / hyphens / underscores /
/// slashes. So "Init system", "init-system", "init_system", "init /
/// system", "InitSystem" all compare equal.
fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_' | '/' | '\t'))
        .flat_map(|c| c.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(label: &str) -> Finding {
        Finding {
            label: label.to_string(),
            value: "x".into(),
            detail: None,
            source: None,
        }
    }

    #[test]
    fn no_filter_returns_all() {
        let out = filter(vec![f("Bootloader"), f("Kernel")], &None, &None);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn only_whitelists_case_insensitive() {
        let out = filter(
            vec![f("Bootloader"), f("Kernel"), f("Network")],
            &Some("bootloader,network".into()),
            &None,
        );
        let labels: Vec<_> = out.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels, vec!["Bootloader", "Network"]);
    }

    #[test]
    fn skip_blacklists_case_insensitive() {
        let out = filter(
            vec![f("Bootloader"), f("Kernel"), f("Network")],
            &None,
            &Some("network".into()),
        );
        let labels: Vec<_> = out.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels, vec!["Bootloader", "Kernel"]);
    }

    #[test]
    fn only_takes_precedence_over_skip() {
        // --only bootloader,kernel --skip kernel yields just Bootloader
        let out = filter(
            vec![f("Bootloader"), f("Kernel"), f("Network")],
            &Some("bootloader,kernel".into()),
            &Some("kernel".into()),
        );
        let labels: Vec<_> = out.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels, vec!["Bootloader"]);
    }

    #[test]
    fn normalization_handles_spaces_hyphens_underscores_slashes() {
        // "Init system", "init-system", "init_system", "CPU / Arch"
        let out = filter(
            vec![f("Init system"), f("CPU / Arch"), f("Kernel")],
            &Some("init_system, cpu-arch".into()),
            &None,
        );
        let labels: Vec<_> = out.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels, vec!["Init system", "CPU / Arch"]);
    }
}
