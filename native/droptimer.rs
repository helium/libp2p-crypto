// Add a DropTimer to the top of a NIF to print to `stderr` anytime
// that NIF runs for too long. Shorter is better, but the general
// guidance is to keep NIFs faster than 1ms, and mark them dirty
// otherwise.
//
// # Usage
//
// ```
// let _timer = DropTimer::new();
// ```
//
pub struct DropTimer(::std::time::Instant);

#[allow(dead_code)]
impl DropTimer {
    pub fn new() -> Self {
        Self(::std::time::Instant::now())
    }
}

impl Drop for DropTimer {
    fn drop(&mut self) {
        let now = std::time::Instant::now();
        let duration = now.duration_since(self.0);
        if duration.as_micros() > 900 {
            eprintln!("Warning, NIF ran for {:?}", duration);
        }
    }
}
