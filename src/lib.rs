use std::ffi::CStr;

use falco_plugin::anyhow::Error;
use falco_plugin::base::{Json, Plugin};
use falco_plugin::tables::TablesInput;
use falco_plugin::{extract_plugin, plugin, source_plugin};
use systemd::journal::OpenOptions;
use systemd::Journal;

use crate::config::{apply_filter, clear_filter, JournalFollowConfig};

pub mod config;
mod extract;
mod source;

pub struct JournalFollowPlugin {
    journal: Journal,
}

impl JournalFollowPlugin {
    fn open_journal(config: JournalFollowConfig) -> Result<Journal, Error> {
        let mut journal = OpenOptions::default().system(true).open()?;

        journal.seek_tail()?;
        apply_filter(&mut journal, config.filter.as_slice())?;
        while journal.next_entry()?.is_some() {
            // flush old journal entries
        }

        Ok(journal)
    }
}

impl Plugin for JournalFollowPlugin {
    const NAME: &'static CStr = c"journald";
    const PLUGIN_VERSION: &'static CStr = c"0.1.0";
    const DESCRIPTION: &'static CStr = c"Journald source for Falco";
    const CONTACT: &'static CStr = c"rust@localdomain.pl";
    type ConfigType = Json<JournalFollowConfig>;

    fn new(_input: Option<&TablesInput>, Json(config): Self::ConfigType) -> Result<Self, Error> {
        let journal = Self::open_journal(config)?;

        Ok(Self { journal })
    }

    fn set_config(&mut self, Json(config): Self::ConfigType) -> Result<(), Error> {
        clear_filter(&mut self.journal)?;
        apply_filter(&mut self.journal, config.filter.as_slice())?;

        Ok(())
    }
}

plugin!(3;3;0 => JournalFollowPlugin);
source_plugin!(JournalFollowPlugin);
extract_plugin!(JournalFollowPlugin);
