use crate::JournalFollowPlugin;
use falco_event::events::types::{EventType, PPME_PLUGINEVENT_E as PluginEvent};
use falco_plugin::anyhow::{anyhow, Error};
use falco_plugin::api::ss_plugin_event_input as EventInput;
use falco_plugin::extract::{
    field, ExtractArgType, ExtractFieldInfo, ExtractFieldRequestArg, ExtractPlugin,
};
use falco_plugin::tables::TableReader;
use falco_plugin::EventInputExt;
use std::ffi::CString;
use systemd::JournalRecord;

impl JournalFollowPlugin {
    fn parse_record<'a>(
        &self,
        context: &'a mut Option<JournalRecord>,
        event: &EventInput,
    ) -> Result<&'a JournalRecord, Error> {
        match context {
            Some(record) => Ok(record),
            None => {
                let event = event.event()?;
                let event = event.load::<PluginEvent>()?;
                let buf = event
                    .params
                    .event_data
                    .ok_or_else(|| anyhow!("Missing event data"))?;

                let record: JournalRecord = serde_json::from_slice(buf)?;
                *context = Some(record);

                Ok(context.as_ref().unwrap())
            }
        }
    }

    fn extract_message(
        &mut self,
        context: &mut Option<JournalRecord>,
        _arg: ExtractFieldRequestArg,
        event: &EventInput,
        _tables: &TableReader,
    ) -> Result<CString, Error> {
        let record = self.parse_record(context, event)?;

        let message = record
            .get("MESSAGE")
            .map(|s| s.clone().into_bytes())
            .unwrap_or_default();
        Ok(CString::new(message)?)
    }

    fn extract_priority(
        &mut self,
        context: &mut Option<JournalRecord>,
        _arg: ExtractFieldRequestArg,
        event: &EventInput,
        _tables: &TableReader,
    ) -> Result<u64, Error> {
        let record = self.parse_record(context, event)?;

        let s = record
            .get("PRIORITY")
            .ok_or_else(|| anyhow!("PRIORITY field not found"))?;
        Ok(s.parse()?)
    }

    fn extract_priority_str(
        &mut self,
        context: &mut Option<JournalRecord>,
        arg: ExtractFieldRequestArg,
        event: &EventInput,
        tables: &TableReader,
    ) -> Result<CString, Error> {
        let prio = self.extract_priority(context, arg, event, tables)?;

        let prio = match prio {
            0 => "emerg",
            1 => "alert",
            2 => "crit",
            3 => "err",
            4 => "warn",
            5 => "notice",
            6 => "info",
            7 => "debug",
            _ => "unknown",
        };

        Ok(CString::new(prio.as_bytes().to_vec())?)
    }

    fn extract_facility(
        &mut self,
        context: &mut Option<JournalRecord>,
        _arg: ExtractFieldRequestArg,
        event: &EventInput,
        _tables: &TableReader,
    ) -> Result<u64, Error> {
        let record = self.parse_record(context, event)?;

        let s = record
            .get("SYSLOG_FACILITY")
            .ok_or_else(|| anyhow!("SYSLOG_FACILITY field not found"))?;
        Ok(s.parse()?)
    }

    fn extract_facility_str(
        &mut self,
        context: &mut Option<JournalRecord>,
        arg: ExtractFieldRequestArg,
        event: &EventInput,
        tables: &TableReader,
    ) -> Result<CString, Error> {
        let fac = self.extract_facility(context, arg, event, tables)?;

        let fac = match fac {
            0 => "kern",
            1 => "user",
            2 => "mail",
            3 => "daemon",
            4 => "auth",
            5 => "syslog",
            6 => "lpr",
            7 => "news",
            8 => "uucp",
            9 => "cron",
            10 => "authpriv",
            11 => "ftp",
            // reserved area
            16 => "local0",
            17 => "local1",
            18 => "local2",
            19 => "local3",
            20 => "local4",
            21 => "local5",
            22 => "local6",
            23 => "local7",
            _ => "unknown",
        };

        Ok(CString::new(fac.as_bytes().to_vec())?)
    }

    fn extract_transport(
        &mut self,
        context: &mut Option<JournalRecord>,
        _arg: ExtractFieldRequestArg,
        event: &EventInput,
        _tables: &TableReader,
    ) -> Result<CString, Error> {
        let record = self.parse_record(context, event)?;

        let message = record
            .get("_TRANSPORT")
            .map(|s| s.clone().into_bytes())
            .ok_or_else(|| anyhow!("_TRANSPORT field not found"))?;
        Ok(CString::new(message)?)
    }

    fn extract_field(
        &mut self,
        context: &mut Option<JournalRecord>,
        arg: ExtractFieldRequestArg,
        event: &EventInput,
        _tables: &TableReader,
    ) -> Result<CString, Error> {
        let record = self.parse_record(context, event)?;
        let ExtractFieldRequestArg::String(arg) = arg else {
            return Err(anyhow!("Unexpected argument {:?}", arg));
        };
        let arg = arg.to_str()?;

        let field = record
            .get(arg)
            .map(|s| s.clone().into_bytes())
            .ok_or_else(|| anyhow!("{} field not found", arg))?;
        Ok(CString::new(field)?)
    }
}

impl ExtractPlugin for JournalFollowPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &["journal"];
    type ExtractContext = Option<JournalRecord>;
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("journal.message", &Self::extract_message),
        field("journal.priority", &Self::extract_priority),
        field("journal.priority_str", &Self::extract_priority_str),
        field("journal.facility", &Self::extract_facility),
        field("journal.facility_str", &Self::extract_facility_str),
        field("journal.transport", &Self::extract_transport),
        field("journal.field", &Self::extract_field).with_arg(ExtractArgType::RequiredKey),
    ];
}
