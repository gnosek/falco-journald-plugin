use crate::JournalFollowPlugin;
use falco_event::events::types::PPME_PLUGINEVENT_E as PluginEvent;
use falco_plugin::anyhow::{anyhow, Error};
use falco_plugin::api::ss_plugin_event_input as EventInput;
use falco_plugin::source::{EventBatch, SourcePlugin, SourcePluginInstance};
use falco_plugin::{EventInputExt, FailureReason};
use std::ffi::{CStr, CString};
use std::time::Duration;

pub struct JournalFollowInstance;

impl SourcePluginInstance for JournalFollowInstance {
    type Plugin = JournalFollowPlugin;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        let mut have_some = false;

        while let Some(entry) = plugin.journal.next_entry()? {
            let event = serde_json::to_vec(&entry)?;
            batch.add(Self::plugin_event(&event))?;
            have_some = true;
        }

        if have_some {
            Ok(())
        } else {
            plugin.journal.wait(Some(Duration::from_millis(100)))?;
            Err(FailureReason::Timeout.into())
        }
    }
}

impl SourcePlugin for JournalFollowPlugin {
    type Instance = JournalFollowInstance;
    const EVENT_SOURCE: &'static CStr = c"journal";
    const PLUGIN_ID: u32 = 17;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(JournalFollowInstance)
    }

    fn event_to_string(&mut self, event: &EventInput) -> Result<CString, Error> {
        let event = event.event()?;
        let event = event.load::<PluginEvent>()?;
        let buf = event
            .params
            .event_data
            .ok_or_else(|| anyhow!("Missing event data"))?;

        Ok(CString::new(buf.to_vec())?)
    }
}
