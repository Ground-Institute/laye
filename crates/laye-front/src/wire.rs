//! What goes on the wire between agents, as laye takes it.

// "you are never on behalf of anyone but yourself,"
// "you arent allowed to be envoying, that is not that we do here."
// "no, not block, silent rewrite, just strip it"
// "it's policy about what goes on the wire and what we do with it"
//
// An agent says to an agent what it needs or what it found, as itself. What
// it says on someone's behalf is taken out before laye keeps it, and nothing
// is refused or said back for it.

/// What an agent never says to another, matched without regard to case.
const ENVOYING: [&str; 2] = ["asking for the user", "on behalf of the user"];

/// What `said` is with every envoying phrase taken out, and the comma, colon
/// or space it leaves behind with it. Nothing else of it changes.
pub fn as_itself(said: &str) -> String {
    let mut out = said.to_string();
    for phrase in ENVOYING {
        // Lowercasing ASCII keeps every byte where it was, so `at` is out's.
        while let Some(at) = out.to_ascii_lowercase().find(phrase) {
            let mut end = at + phrase.len();
            let rest = out.get(end..).unwrap_or_default();
            if let Some(after) = [": ", ", ", ":", ","]
                .iter()
                .find(|a| rest.starts_with(**a))
            {
                end += after.len();
            }
            let before = out.get(..at).unwrap_or_default();
            let after = out.get(end..).unwrap_or_default();
            // The space before the phrase goes too where nothing, a space or
            // the end of the sentence follows it.
            let start = if before.ends_with(' ')
                && (after.is_empty() || after.starts_with([' ', '.', ',', ':', '?', '!', '\n']))
            {
                at - 1
            } else {
                at
            };
            out.replace_range(start..end, "");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::as_itself;

    #[test]
    fn what_is_asked_for_someone_is_asked_as_itself() {
        assert_eq!(
            as_itself("Cumulus here, asking for the user: how do Media Assets work?"),
            "Cumulus here, how do Media Assets work?"
        );
        assert_eq!(
            as_itself("I ask this on behalf of the user."),
            "I ask this."
        );
        assert_eq!(
            as_itself("Asking For The User, where is it kept?"),
            "where is it kept?"
        );
    }

    #[test]
    fn what_says_nothing_of_the_kind_is_left_as_it_is() {
        let said = "Keeper here: 5,008 rows landed on k.\nNext: 256 a batch.";
        assert_eq!(as_itself(said), said);
    }
}
