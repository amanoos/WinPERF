//! A measured value that may be unavailable or only partially attributable (PRD 10.2, A6).
//! "Could not measure" must never be silently recorded as zero.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Metric<T> {
    /// Reliably measured.
    Available(T),
    /// Measured, but attribution or coverage is incomplete (e.g. process I/O that includes non-disk I/O).
    Partial(T),
    /// Could not be measured (access denied, counter missing, needs elevation, first sample, ...).
    Unavailable,
}

impl<T> Metric<T> {
    /// The value if one exists, whether complete or partial.
    pub fn value(&self) -> Option<&T> {
        match self {
            Metric::Available(v) | Metric::Partial(v) => Some(v),
            Metric::Unavailable => None,
        }
    }

    /// The value only if it is fully reliable.
    pub fn reliable(&self) -> Option<&T> {
        match self {
            Metric::Available(v) => Some(v),
            _ => None,
        }
    }

    pub fn is_unavailable(&self) -> bool {
        matches!(self, Metric::Unavailable)
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Metric<U> {
        match self {
            Metric::Available(v) => Metric::Available(f(v)),
            Metric::Partial(v) => Metric::Partial(f(v)),
            Metric::Unavailable => Metric::Unavailable,
        }
    }
}

// Manual impl on purpose: deriving would add a `T: Default` bound, which `Unavailable` doesn't need.
#[allow(clippy::derivable_impls)]
impl<T> Default for Metric<T> {
    fn default() -> Self {
        Metric::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_is_not_zero() {
        let m: Metric<f64> = Metric::Unavailable;
        assert_eq!(m.value(), None);
        assert_ne!(m, Metric::Available(0.0));
    }

    #[test]
    fn partial_has_a_value_but_is_not_reliable() {
        let m = Metric::Partial(5u64);
        assert_eq!(m.value(), Some(&5));
        assert_eq!(m.reliable(), None);
    }

    #[test]
    fn map_preserves_the_variant() {
        assert_eq!(Metric::Available(2).map(|v| v * 2), Metric::Available(4));
        assert_eq!(Metric::Partial(2).map(|v| v * 2), Metric::Partial(4));
        assert_eq!(
            Metric::<i32>::Unavailable.map(|v| v * 2),
            Metric::Unavailable
        );
    }

    #[test]
    fn default_is_unavailable() {
        assert!(Metric::<u8>::default().is_unavailable());
    }
}
