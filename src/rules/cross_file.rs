//! Cross-file taint analysis infrastructure.
//!
//! Provides [`FunctionTaintSummary`] — a compact description of how a function
//! propagates taint from its parameters to sinks and return values. Summaries
//! are generated in pass 1 of the scanner (one per exported function) and
//! consumed in pass 2 by the per-file taint engines.
//!
//! The summary extraction reuses the existing single-file taint engine: each
//! parameter is treated as a synthetic taint source, and any findings or
//! return-taint that result are recorded in the summary.

use std::collections::HashMap;
use std::path::PathBuf;

/// Summary of a function's taint behavior for cross-file analysis.
/// Generated in pass 1, consumed in pass 2.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionTaintSummary {
    /// Function name as exported.
    pub name: String,
    /// Which parameter indices, when tainted, cause the return value to be tainted.
    pub params_to_return: Vec<usize>,
    /// Which parameter indices, when tainted, reach a sink.
    pub params_to_sink: Vec<ParamSinkFlow>,
}

impl FunctionTaintSummary {
    /// Merge newly-discovered flows from `other` (a re-analysis of the same
    /// function with cross-file resolution enabled) into `self`, unioning
    /// `params_to_return` and `params_to_sink`. A `params_to_sink` entry is
    /// considered a duplicate when it has the same `(param_index, sink_rule_id)`
    /// pair — the sink description is not part of the identity.
    ///
    /// Returns `true` if any new flow was added, which the scanner's bounded
    /// multi-hop fixpoint uses as its "changed" signal for early termination.
    pub fn merge_from(&mut self, other: &FunctionTaintSummary) -> bool {
        let mut changed = false;
        for &p in &other.params_to_return {
            if !self.params_to_return.contains(&p) {
                self.params_to_return.push(p);
                changed = true;
            }
        }
        for flow in &other.params_to_sink {
            let dup = self
                .params_to_sink
                .iter()
                .any(|f| f.param_index == flow.param_index && f.sink_rule_id == flow.sink_rule_id);
            if !dup {
                self.params_to_sink.push(flow.clone());
                changed = true;
            }
        }
        changed
    }
}

/// Records that when parameter at `param_index` is tainted, it reaches
/// a specific sink identified by the rule that would fire.
#[derive(Debug, Clone, PartialEq)]
pub struct ParamSinkFlow {
    pub param_index: usize,
    pub sink_rule_id: String,
    pub sink_description: String,
}

/// Map from file path to the summaries of all exported functions in that file.
pub type CrossFileSummaryMap = HashMap<PathBuf, Vec<FunctionTaintSummary>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(idx: usize, rule: &str) -> ParamSinkFlow {
        ParamSinkFlow {
            param_index: idx,
            sink_rule_id: rule.to_string(),
            sink_description: "sink".to_string(),
        }
    }

    #[test]
    fn merge_from_unions_new_flows_and_reports_changed() {
        let mut base = FunctionTaintSummary {
            name: "f".into(),
            params_to_return: vec![0],
            params_to_sink: vec![flow(0, "r1")],
        };
        let other = FunctionTaintSummary {
            name: "f".into(),
            params_to_return: vec![0, 1], // 1 is new
            params_to_sink: vec![flow(0, "r1"), flow(1, "r2")], // (1,r2) is new
        };
        assert!(base.merge_from(&other), "new flows should report changed");
        assert_eq!(base.params_to_return, vec![0, 1]);
        assert_eq!(base.params_to_sink.len(), 2);
        assert!(base
            .params_to_sink
            .iter()
            .any(|f| f.param_index == 1 && f.sink_rule_id == "r2"));
    }

    #[test]
    fn merge_from_is_idempotent_when_nothing_new() {
        let mut base = FunctionTaintSummary {
            name: "f".into(),
            params_to_return: vec![0],
            params_to_sink: vec![flow(0, "r1")],
        };
        // Same (param_index, sink_rule_id) identity even if description differs.
        let dup = FunctionTaintSummary {
            name: "f".into(),
            params_to_return: vec![0],
            params_to_sink: vec![ParamSinkFlow {
                param_index: 0,
                sink_rule_id: "r1".into(),
                sink_description: "different-description".into(),
            }],
        };
        assert!(
            !base.merge_from(&dup),
            "no new flow should report unchanged"
        );
        assert_eq!(base.params_to_sink.len(), 1);
    }
}
