//! Calendar operations used by the date-parsing probe, in the host time zone.

use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveDate, NaiveTime, TimeZone, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::engine::Engine;
use crate::js::{JsObject, json};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference;

/// The historical years the probe parses.
const YEARS: [i32; 5] = [999, 1060, 1937, 1945, 1989];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    /// The field reporting each historical year's parsing difference, in program order.
    pub years: IndexMap<String, i32>,
}

impl Fields {
    /// Collects date-parsing results for the current time in the host time zone, using
    /// `engine`'s rules.
    pub fn collect(&self, engine: Engine) -> Result<JsObject> {
        let name = iana_time_zone::get_timezone().context("reading the host IANA time zone")?;
        self.collect_in(&Local, &name, Utc::now(), engine)
    }

    /// Collects dates in `zone` at `now`, reporting the zone as `name`.
    fn collect_in<Tz: TimeZone>(
        &self,
        zone: &Tz,
        name: &str,
        now: DateTime<Utc>,
        engine: Engine,
    ) -> Result<JsObject> {
        use chrono::Offset;

        let mut result = JsObject::new();
        for (field, &year) in &self.years {
            // V8 parses both three-digit year forms as local dates, so their difference is
            // zero. JavaScriptCore parses them like four-digit years, whose ISO form uses UTC
            // and slash form local time.
            let minutes = if year == 999 && engine == Engine::Chromium {
                0
            } else {
                let date = NaiveDate::from_ymd_opt(year, 12, 1)
                    .context("invalid historical probe date")?;
                -local_minus_utc_minutes(zone, date)?
            };
            result.insert(field.clone(), json!(minutes));
        }
        // JSON.stringify(new Date()) supplies the UTC date, which is then parsed twice:
        // mm/dd/yyyy in the local zone and yyyy-mm-dd in UTC.
        result.insert(
            reference::DATES_TODAY.to_owned(),
            json!(local_minus_utc_minutes(zone, now.date_naive())?),
        );
        result.insert(
            reference::DATES_OFFSET.to_owned(),
            json!(-now.with_timezone(zone).offset().fix().local_minus_utc() / 60),
        );
        result.insert(reference::DATES_ZONE.to_owned(), json!(name));
        Ok(result)
    }
}

fn local_minus_utc_minutes<Tz: TimeZone>(zone: &Tz, date: NaiveDate) -> Result<i64> {
    let midnight = date.and_time(NaiveTime::MIN);
    let local = zone
        .from_local_datetime(&midnight)
        .earliest()
        .context("local midnight does not exist")?;
    Ok((local.timestamp_millis() - midnight.and_utc().timestamp_millis()) / 60000)
}

/// Recovers output fields for the five historical years. Each field name precedes its year in
/// the probe's strings.
pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let strings = &probe.strings;
    let outputs = [
        reference::DATES_TODAY,
        reference::DATES_OFFSET,
        reference::DATES_ZONE,
    ];
    if !(strings.has("getTimezoneOffset") && strings.stores_all(&outputs)) {
        return None;
    }
    let years: IndexMap<String, i32> = strings
        .features()
        .windows(2)
        .filter_map(|pair| {
            let year: i32 = pair[1].parse().ok()?;
            (YEARS.contains(&year) && strings.stores(&pair[0])).then(|| (pair[0].clone(), year))
        })
        .collect();
    (years.len() == YEARS.len()).then_some(Fields { years })
}

#[cfg(test)]
mod tests {
    use chrono::FixedOffset;

    use super::*;
    use crate::js::{self, JsValue};

    fn fields() -> Fields {
        js::from_value(json!({"years": {"legacy": 999, "old": 1060, "winter": 1989}})).unwrap()
    }

    #[test]
    fn offsets_count_minutes_west_of_utc_in_each_engine() {
        let zone = FixedOffset::west_opt(5 * 3600).unwrap();
        let now = DateTime::from_timestamp_millis(1791160488831).unwrap();
        let collect = |engine| fields().collect_in(&zone, "Etc/GMT+5", now, engine);
        assert_eq!(
            JsValue::Object(collect(Engine::Chromium).unwrap()),
            json!({"legacy":0, "old":-300, "winter":-300, (reference::DATES_TODAY):300,
                (reference::DATES_OFFSET):300, (reference::DATES_ZONE):"Etc/GMT+5"})
        );
        // iOS Safari in New York reports the zone's mean time for both historical years.
        let webkit = collect(Engine::WebKit).unwrap();
        assert_eq!(webkit["legacy"], -300);
        assert_eq!(webkit["legacy"], webkit["old"]);
    }

    #[test]
    fn historical_offsets_keep_their_sign_in_the_host_zone() {
        let now = DateTime::from_timestamp_millis(1791160488831).unwrap();
        let name = iana_time_zone::get_timezone().unwrap();
        let result = fields()
            .collect_in(&Local, &name, now, Engine::Chromium)
            .unwrap();
        assert_eq!(result["legacy"], 0);
        // The fixed values hold in New York; other hosts still run the arithmetic.
        if result[reference::DATES_ZONE] == "America/New_York" {
            assert_eq!(result["old"], -296);
            assert_eq!(result["winter"], -300);
            assert_eq!(result[reference::DATES_TODAY], 240);
            assert_eq!(result[reference::DATES_OFFSET], 240);
        }
    }
}
