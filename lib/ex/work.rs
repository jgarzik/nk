//! Dynamic worker pool sizing for the executive's work queues
//! (`kernel/ex/work.rs`).
//!
//! Each work queue keeps at least `min` workers and grows up to `max`
//! when queued items sit waiting with no idle worker to take them.
//! Extra workers retire when they time out idle with no work queued.

/// A queue's dynamic worker counts, held under the queue's spin lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pool {
    /// Minimum workers kept alive.
    min: u32,
    /// Maximum workers allowed.
    max: u32,
    /// Workers currently alive (base and dynamic).
    workers: u32,
    /// Workers currently executing a work item.
    busy: u32,
    /// Work items currently waiting on the queue.
    queued: u32,
    /// Dynamic workers whose creation is in flight.
    spawning: u32,
}

impl Pool {
    /// A pool starting with `min` base workers and growing up to `max`.
    pub const fn new(min: u32, max: u32) -> Self {
        Self {
            min,
            max,
            workers: min,
            busy: 0,
            queued: 0,
            spawning: 0,
        }
    }

    /// Current live worker count.
    pub const fn workers(&self) -> u32 {
        self.workers
    }

    /// Whether items are waiting with no idle worker to take them and
    /// room remains under the queue's cap.
    pub const fn wants_worker(&self) -> bool {
        let idle = self.workers.saturating_sub(self.busy);
        self.queued > idle && self.workers + self.spawning < self.max
    }

    /// Record a work item queued. Returns `true` if the spawner should
    /// be woken to consider growing the pool.
    pub fn on_queue(&mut self) -> bool {
        self.queued += 1;
        self.wants_worker()
    }

    /// Record a worker taking an item off the queue. Returns `true` if
    /// more items remain waiting without an idle worker.
    pub fn on_dequeue(&mut self) -> bool {
        self.queued = self.queued.saturating_sub(1);
        self.busy += 1;
        self.wants_worker()
    }

    /// Record a worker finishing its item.
    pub fn on_done(&mut self) {
        self.busy = self.busy.saturating_sub(1);
    }

    /// Called by the spawner after its grace delay: claim a spawn slot
    /// if the queue still needs another worker.
    pub fn begin_spawn(&mut self) -> bool {
        if !self.wants_worker() {
            return false;
        }
        self.spawning += 1;
        true
    }

    /// The claimed dynamic worker was created and made ready.
    pub fn spawn_succeeded(&mut self) {
        self.spawning = self.spawning.saturating_sub(1);
        self.workers += 1;
    }

    /// Creating the claimed dynamic worker failed (no memory).
    pub fn spawn_failed(&mut self) {
        self.spawning = self.spawning.saturating_sub(1);
    }

    /// Called when a worker's idle wait timed out. Returns `true` if
    /// this worker should retire (leaving at least `min` workers and
    /// retiring only when no work is queued).
    pub fn on_idle_timeout(&mut self) -> bool {
        if self.workers > self.min && self.queued == 0 {
            self.workers -= 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_spawn_while_idle_workers_cover_queue() {
        let mut pool = Pool::new(2, 8);
        assert_eq!(pool.workers(), 2);
        assert!(!pool.on_queue());
        assert!(!pool.on_queue());
        assert!(!pool.begin_spawn());
        // A third item exceeds the two idle workers.
        assert!(pool.on_queue());
        // If two workers dequeue two items, one item still waits with no idle worker.
        assert!(pool.on_dequeue());
        assert!(pool.on_dequeue());
        // Once they finish and the third is taken, no spawn is wanted.
        pool.on_done();
        assert!(!pool.on_dequeue());
        pool.on_done();
        pool.on_done();
        assert!(!pool.wants_worker());
    }

    #[test]
    fn spawn_lifecycle_and_cap() {
        let mut pool = Pool::new(1, 3);
        // Occupy the base worker.
        assert!(!pool.on_queue());
        assert!(!pool.on_dequeue());
        // Queue two more items while busy.
        assert!(pool.on_queue());
        assert!(pool.on_queue());
        // Claim two spawns up to max = 3.
        assert!(pool.begin_spawn());
        assert!(pool.begin_spawn());
        // At cap: no more spawns allowed.
        assert!(!pool.begin_spawn());
        // One fails, one succeeds.
        pool.spawn_failed();
        assert_eq!(pool.workers(), 1);
        pool.spawn_succeeded();
        assert_eq!(pool.workers(), 2);
        // Room for one more again.
        assert!(pool.begin_spawn());
        pool.spawn_succeeded();
        assert_eq!(pool.workers(), 3);
        assert!(!pool.begin_spawn());
    }

    #[test]
    fn retire_only_above_min_and_when_empty() {
        let mut pool = Pool::new(2, 6);
        // Base workers never retire.
        assert!(!pool.on_idle_timeout());
        assert_eq!(pool.workers(), 2);

        // Grow to 4 workers.
        for _ in 0..4 {
            pool.on_queue();
        }
        assert!(pool.begin_spawn());
        pool.spawn_succeeded();
        assert!(pool.begin_spawn());
        pool.spawn_succeeded();
        assert_eq!(pool.workers(), 4);

        // With items still queued, idle timeout does not retire.
        assert!(!pool.on_idle_timeout());
        assert_eq!(pool.workers(), 4);

        // Drain the queue.
        for _ in 0..4 {
            pool.on_dequeue();
            pool.on_done();
        }
        // Now extra workers retire one by one down to min.
        assert!(pool.on_idle_timeout());
        assert_eq!(pool.workers(), 3);
        assert!(pool.on_idle_timeout());
        assert_eq!(pool.workers(), 2);
        // Back at min: stays at 2.
        assert!(!pool.on_idle_timeout());
        assert_eq!(pool.workers(), 2);
    }
}
