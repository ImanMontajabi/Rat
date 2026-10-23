use std::time::{Duration, Instant};
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum SortOrder {
    #[default]
    Name,
    Recent,
    Count,
}
impl SortOrder {
    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Recent => "Recent",
            Self::Count => "Sockets",
        }
    }
    pub fn compare(self, a: (&str, usize, u64), b: (&str, usize, u64)) -> std::cmp::Ordering {
        let alphabetical = || {
            a.0.to_lowercase()
                .cmp(&b.0.to_lowercase())
                .then(a.0.cmp(b.0))
        };
        match self {
            Self::Name => alphabetical(),
            Self::Recent => b.2.cmp(&a.2).then_with(alphabetical),
            Self::Count => b.1.cmp(&a.1).then_with(alphabetical),
        }
    }
}
pub struct RowMotion {
    from: f32,
    to: f32,
    start: Instant,
}
impl RowMotion {
    pub fn new(position: f32, now: Instant) -> Self {
        Self {
            from: position,
            to: position,
            start: now,
        }
    }
    fn position(&self, now: Instant) -> f32 {
        let t = (now.duration_since(self.start).as_secs_f32() / 0.22).clamp(0., 1.);
        self.from + (self.to - self.from) * (1. - (1. - t).powi(3))
    }
    pub fn offset(&mut self, target: f32, now: Instant, animate: bool) -> (f32, bool) {
        if !animate {
            *self = Self::new(target, now);
            return (0., false);
        }
        if self.to != target {
            self.from = self.position(now);
            self.to = target;
            self.start = now;
        }
        let active =
            self.from != self.to && now.duration_since(self.start) < Duration::from_millis(220);
        (self.position(now) - self.to, active)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activity_ties_keep_stable_names() {
        assert!(
            SortOrder::Count
                .compare(("Browser", 4, 1), ("Chat", 4, 99))
                .is_lt()
        );
        assert!(
            SortOrder::Recent
                .compare(("Chat", 1, 20), ("Browser", 10, 2))
                .is_lt()
        );
        assert!(
            SortOrder::Name
                .compare(("Chat", 1, 20), ("browser", 10, 2))
                .is_gt()
        );
    }
    #[test]
    fn interrupted_reorder_starts_at_current_visual_position() {
        let now = Instant::now();
        let mut m = RowMotion::new(0., now);
        assert_eq!(m.offset(84., now, true), (-84., true));
        let later = now + Duration::from_millis(110);
        let before = m.position(later);
        let (offset, active) = m.offset(42., later, true);
        assert!(active);
        assert!((offset + 42. - before).abs() < 0.001);
        assert_eq!(
            m.offset(42., later + Duration::from_millis(221), true),
            (0., false)
        );
        assert_eq!(
            m.offset(0., later + Duration::from_millis(222), false),
            (0., false)
        );
    }
}
