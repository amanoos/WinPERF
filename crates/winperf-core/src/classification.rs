//! Publisher classification (PRD FR-002).
//!
//! A Microsoft signature identifies the *publisher*, not whether something is a core Windows
//! component (PRD 10.6). This enum is only the publisher/signature classification.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Classification {
    /// Valid Authenticode signature from Microsoft.
    MicrosoftOfficial,
    /// Valid signature from another publisher.
    ThirdPartyOfficial,
    /// No valid signature.
    Unsigned,
    /// Publisher or signature state could not be established (e.g. file unreadable).
    Unknown,
}

impl Classification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Classification::MicrosoftOfficial => "microsoft",
            Classification::ThirdPartyOfficial => "third_party",
            Classification::Unsigned => "unsigned",
            Classification::Unknown => "unknown",
        }
    }

    /// Parse the stable storage/export representation.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "microsoft" => Classification::MicrosoftOfficial,
            "third_party" => Classification::ThirdPartyOfficial,
            "unsigned" => Classification::Unsigned,
            "unknown" => Classification::Unknown,
            _ => return None,
        })
    }
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Classification; 4] = [
        Classification::MicrosoftOfficial,
        Classification::ThirdPartyOfficial,
        Classification::Unsigned,
        Classification::Unknown,
    ];

    #[test]
    fn string_form_round_trips() {
        for c in ALL {
            assert_eq!(Classification::parse(c.as_str()), Some(c));
        }
    }

    #[test]
    fn unknown_string_is_rejected() {
        assert_eq!(Classification::parse("Microsoft"), None);
        assert_eq!(Classification::parse(""), None);
    }
}
