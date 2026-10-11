use anyhow::Result;
use shadowapi_reconstructor::Event;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct Sender {
    url: String,
    buf: Vec<Event>,
    last: Instant,
}

impl Sender {
    pub fn new(base: &str) -> Self {
        Self { url: format!("{}/events", base.trim_end_matches('/')), buf: vec![], last: Instant::now() }
    }

    pub fn push(&mut self, mut ev: Event) {
        ev.ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
        self.buf.push(ev);
        if self.buf.len() >= 100 {
            let _ = self.flush();
        }
    }

    /// Flush if there is anything pending and `every` has elapsed (call from an idle loop).
    pub fn tick(&mut self, every: Duration) {
        if !self.buf.is_empty() && self.last.elapsed() >= every {
            let _ = self.flush();
        }
    }

    pub fn flush(&mut self) -> Result<()> {
        self.last = Instant::now();
        if self.buf.is_empty() {
            return Ok(());
        }
        let res = ureq::post(&self.url).send_json(serde_json::to_value(&self.buf)?);
        match res {
            Ok(_) => self.buf.clear(),
            Err(e) => {
                eprintln!("detector unreachable: {e}");
                if self.buf.len() > 5000 {
                    self.buf.drain(..2500); // bounded memory while the detector is down
                }
                return Err(e.into());
            }
        }
        Ok(())
    }
}
