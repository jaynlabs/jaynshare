//! The tool's deadline never below (hold hint + 60) × 1000 ms.
//! The existing value is the inherited one, or the tool's default when it
//! is absent: the launch raises it to the floor and never
//! lowers it, so an absent variable stays absent unless the floor exceeds
//! the default. Untouched when the snapshot was unreadable (`hold_hint` is
//! `None`).

use super::EnvPlan;
use crate::provider::Deadline;

pub fn apply(
    plan: &mut EnvPlan,
    deadline: &Deadline,
    hold_hint: Option<u64>,
    inherited: Option<&str>,
) {
    let Some(hint) = hold_hint else {
        return;
    };
    let floor = (hint + 60) * 1000;
    let existing = inherited
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(deadline.default_ms);
    if existing >= floor {
        return;
    }
    plan.set(deadline.variable, floor.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEADLINE: Deadline = Deadline {
        variable: "API_TIMEOUT_MS",
        default_ms: 600_000,
    };

    #[test]
    fn leaves_the_variable_absent_below_claude_s_default() {
        let mut plan = EnvPlan::default();
        apply(&mut plan, &DEADLINE, Some(30), None);
        assert_eq!(plan.get("API_TIMEOUT_MS"), None);
        apply(&mut plan, &DEADLINE, Some(540), None);
        assert_eq!(plan.get("API_TIMEOUT_MS"), None);
    }

    #[test]
    fn sets_the_floor_above_claude_s_default() {
        let mut plan = EnvPlan::default();
        apply(&mut plan, &DEADLINE, Some(541), None);
        assert_eq!(plan.get("API_TIMEOUT_MS"), Some("601000"));
    }

    #[test]
    fn never_lowers_a_larger_inherited_value() {
        let mut plan = EnvPlan::default();
        apply(&mut plan, &DEADLINE, Some(30), Some("120000"));
        assert_eq!(plan.get("API_TIMEOUT_MS"), None);
    }

    #[test]
    fn raises_a_smaller_inherited_value() {
        let mut plan = EnvPlan::default();
        apply(&mut plan, &DEADLINE, Some(30), Some("5000"));
        assert_eq!(plan.get("API_TIMEOUT_MS"), Some("90000"));
    }

    #[test]
    fn leaves_the_variable_untouched_when_the_snapshot_was_unreadable() {
        let mut plan = EnvPlan::default();
        apply(&mut plan, &DEADLINE, None, Some("5000"));
        assert_eq!(plan.get("API_TIMEOUT_MS"), None);
    }

    #[test]
    fn hint_zero_gives_the_60_s_floor() {
        let mut plan = EnvPlan::default();
        apply(&mut plan, &DEADLINE, Some(0), Some("1000"));
        assert_eq!(plan.get("API_TIMEOUT_MS"), Some("60000"));
    }
}
