use falco_plugin::schemars;
use falco_plugin::serde::{Deserialize, Deserializer};
use foreign_types::ForeignType;
use libsystemd_sys;
use schemars::gen::SchemaGenerator;
use schemars::schema::Schema;
use schemars::JsonSchema;
use systemd::{sd_try, Journal};

#[derive(Debug)]
pub enum JournalFilter {
    Or,
    And,
    Match(String),
}

impl JsonSchema for JournalFilter {
    fn schema_name() -> String {
        "journal_filter".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        String::json_schema(gen)
    }
}

impl<'de> Deserialize<'de> for JournalFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        match s.as_str() {
            "OR" => Ok(JournalFilter::Or),
            "AND" => Ok(JournalFilter::And),
            _ => Ok(JournalFilter::Match(s)),
        }
    }
}

pub fn apply_filter(journal: &mut Journal, filter: &[JournalFilter]) -> Result<(), std::io::Error> {
    let journal = journal.as_ptr();
    for f in filter {
        match f {
            JournalFilter::Or => {
                sd_try!(libsystemd_sys::journal::sd_journal_add_disjunction(journal))
            }
            JournalFilter::And => {
                sd_try!(libsystemd_sys::journal::sd_journal_add_conjunction(journal))
            }
            JournalFilter::Match(m) => sd_try!(libsystemd_sys::journal::sd_journal_add_match(
                journal,
                m.as_ptr().cast(),
                m.len()
            )),
        };
    }

    Ok(())
}

pub fn clear_filter(journal: &mut Journal) -> Result<(), std::io::Error> {
    let journal = journal.as_ptr();
    unsafe {
        libsystemd_sys::journal::sd_journal_flush_matches(journal);
    }

    Ok(())
}

#[derive(Deserialize, JsonSchema)]
pub struct JournalFollowConfig {
    pub filter: Vec<JournalFilter>,
}
