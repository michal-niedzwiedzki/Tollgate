use std::time::Instant;

/// Records elapsed time into the `tollgate_stage_seconds` histogram, labelled by `stage`, when
/// dropped. Covers early returns and errors the same as the happy path, since drop runs
/// regardless of how the scope is exited.
pub struct StageTimer {
    stage: &'static str,
    start: Instant,
}

impl StageTimer {
    pub fn start(stage: &'static str) -> Self {
        StageTimer {
            stage,
            start: Instant::now(),
        }
    }
}

impl Drop for StageTimer {
    fn drop(&mut self) {
        metrics::histogram!("tollgate_stage_seconds", "stage" => self.stage)
            .record(self.start.elapsed().as_secs_f64());
    }
}
