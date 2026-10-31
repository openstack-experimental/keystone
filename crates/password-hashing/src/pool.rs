// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Dedicated execution pool for the CPU bound password hashing work.
//!
//! Hashing and verifying passwords is deliberately expensive. Running it on
//! tokio's shared blocking pool (up to 512 threads) lets a burst of logins
//! occupy every core and starve the async workers and every other blocking
//! user. This module gives the hashers their own fixed set of OS threads fed
//! by a bounded queue, so that during saturation only the password hashing
//! requests wait in line, while the rest of the service keeps its CPU share.
//!
//! The queue bound is enforced with a semaphore: a job has to hold a slot from
//! the moment it is submitted until a hashing thread picks it up. What happens
//! when no slot is free is a per-call decision, see
//! [`PasswordHashingQueueFull`].

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, PoisonError};
use std::time::Instant;

use openstack_keystone_config::{Config, PasswordHashingQueueFull};
use openstack_keystone_telemetry::metrics::{
    self, CounterVec, HistogramVec, Label, UpDownCounterVec,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, oneshot};
use tracing::{debug, error, warn};

use super::PasswordHashError;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// Upper bound for the number of hashing threads. Larger configured values are
/// clamped so that a typo cannot try to start millions of OS threads.
const MAX_THREADS: usize = 1024;

/// Upper bound for the number of queue slots. Larger configured values are
/// clamped (the semaphore panics when it overflows its permit limit).
const MAX_QUEUE_SIZE: usize = 1_000_000;

/// Bring configured sizes into the supported range `1..=MAX`.
fn clamp_sizes(threads: usize, queue_size: usize) -> (usize, usize) {
    let clamped = (
        threads.clamp(1, MAX_THREADS),
        queue_size.clamp(1, MAX_QUEUE_SIZE),
    );
    if clamped != (threads, queue_size) {
        warn!(
            threads,
            queue_size,
            used_threads = clamped.0,
            used_queue_size = clamped.1,
            "password hashing pool size is out of range and was clamped"
        );
    }
    clamped
}

/// A queue slot. Giving it back (by dropping it) settles the shrink debt first,
/// so that every path that ends the life of a queued job, including a job that
/// is dropped without ever running, accounts for a shrunken queue.
struct Slot {
    permit: Option<OwnedSemaphorePermit>,
    debt: Arc<AtomicUsize>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            release_slot(permit, &self.debt);
        }
    }
}

/// Buckets (seconds) for the time a job waits for a free hashing thread.
const WAIT_BUCKETS: [f64; 10] = [0.001, 0.005, 0.025, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0, 30.0];

/// Metrics of the password hashing pool (ADR 0031).
struct PoolMetrics {
    /// `keystone_password_hashing_rejected_total{behavior}`.
    rejected_total: CounterVec<1>,
    /// `keystone_password_hashing_queue_depth`.
    queue_depth: UpDownCounterVec<0>,
    /// `keystone_password_hashing_queue_wait_seconds`.
    queue_wait: HistogramVec<0>,
}

static METRICS: LazyLock<PoolMetrics> = LazyLock::new(|| {
    let meter = metrics::meter();
    PoolMetrics {
        rejected_total: CounterVec::new(
            &meter,
            "keystone_password_hashing_rejected_total",
            "Password hashing jobs rejected because the queue was full.",
            ["behavior"],
        ),
        queue_depth: UpDownCounterVec::new(
            &meter,
            "keystone_password_hashing_queue_depth",
            "Password hashing jobs waiting for a free hashing thread.",
            [],
        ),
        queue_wait: HistogramVec::new(
            &meter,
            "keystone_password_hashing_queue_wait_seconds",
            "Time a password hashing job waited for a free hashing thread.",
            [],
            &WAIT_BUCKETS,
        ),
    }
});

/// Message to a worker thread.
enum Message {
    /// Run a hashing job.
    Run(Job),
    /// Ask a worker to exit when there are more workers than wanted.
    Retire,
}

/// State shared between the pool and its worker threads.
struct Shared {
    /// Message queue feeding the worker threads.
    receiver: Mutex<Receiver<Message>>,
    /// Number of workers that should be running.
    target: AtomicUsize,
    /// Number of workers that are running.
    live: AtomicUsize,
}

/// Sizing state that is only touched while resizing.
struct Sizing {
    /// Number of queue slots in effect.
    queue_size: usize,
    /// Index for naming the next worker thread.
    next_index: usize,
}

/// A set of OS threads executing password hashing jobs.
///
/// The number of threads and the size of the queue can be changed while the
/// pool is in use, see [`HashingPool::resize`].
pub(crate) struct HashingPool {
    /// Job queue feeding the worker threads.
    sender: Sender<Message>,
    /// One permit per free slot in the queue.
    slots: Arc<Semaphore>,
    /// Slots that still have to be taken away after the queue shrank while its
    /// slots were in use.
    debt: Arc<AtomicUsize>,
    shared: Arc<Shared>,
    sizing: Mutex<Sizing>,
}

impl HashingPool {
    /// Start `threads` workers with room for `queue_size` jobs waiting for
    /// them. Both are clamped to the supported range.
    pub(crate) fn new(threads: usize, queue_size: usize) -> Self {
        let (threads, queue_size) = clamp_sizes(threads, queue_size);
        let (sender, receiver) = channel::<Message>();
        let pool = Self {
            sender,
            slots: Arc::new(Semaphore::new(queue_size)),
            debt: Arc::new(AtomicUsize::new(0)),
            shared: Arc::new(Shared {
                receiver: Mutex::new(receiver),
                target: AtomicUsize::new(threads),
                live: AtomicUsize::new(0),
            }),
            sizing: Mutex::new(Sizing {
                queue_size,
                next_index: 0,
            }),
        };
        {
            let mut sizing = pool.sizing();
            pool.spawn_workers(&mut sizing, threads);
        }
        debug!(
            threads = pool.live_threads(),
            queue_size, "password hashing pool started"
        );
        pool
    }

    fn sizing(&self) -> std::sync::MutexGuard<'_, Sizing> {
        self.sizing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of running worker threads.
    pub(crate) fn live_threads(&self) -> usize {
        self.shared.live.load(Ordering::SeqCst)
    }

    /// Start `count` more workers. Failing to start one is logged: the next
    /// resize tries again.
    fn spawn_workers(&self, sizing: &mut Sizing, count: usize) {
        for _ in 0..count {
            let index = sizing.next_index;
            sizing.next_index += 1;
            // Counted before the thread starts so that a retire message
            // never sees fewer workers than there are.
            self.shared.live.fetch_add(1, Ordering::SeqCst);
            let shared = self.shared.clone();
            if let Err(err) = std::thread::Builder::new()
                .name(format!("pwd-hash-{index}"))
                .spawn(move || worker(&shared))
            {
                self.shared.live.fetch_sub(1, Ordering::SeqCst);
                error!(%err, "failed to start a password hashing thread");
            }
        }
    }

    /// Start the workers that are missing (for example because starting them
    /// failed earlier). Returns the number of running workers.
    fn ensure_workers(&self) -> usize {
        let mut sizing = self.sizing();
        let target = self.shared.target.load(Ordering::SeqCst);
        let live = self.live_threads();
        if live < target {
            self.spawn_workers(&mut sizing, target - live);
        }
        self.live_threads()
    }

    /// Change the number of threads and the size of the queue.
    ///
    /// Growing takes effect immediately. When shrinking, running jobs are
    /// never interrupted: a busy surplus thread exits as soon as it finishes
    /// its current job, an idle one when it receives a retire message. Queue
    /// slots that are in use are taken away when they are released.
    pub(crate) fn resize(&self, threads: usize, queue_size: usize) {
        let (threads, queue_size) = clamp_sizes(threads, queue_size);
        let mut sizing = self.sizing();

        if queue_size > sizing.queue_size {
            let grow = queue_size - sizing.queue_size;
            let grow = grow - take_debt(&self.debt, grow);
            self.slots.add_permits(grow);
        } else if queue_size < sizing.queue_size {
            let mut shrink = sizing.queue_size - queue_size;
            while shrink > 0 {
                match self.slots.try_acquire() {
                    Ok(permit) => {
                        permit.forget();
                        shrink -= 1;
                    }
                    Err(_) => break,
                }
            }
            self.debt.fetch_add(shrink, Ordering::SeqCst);
        }
        let old_queue_size = std::mem::replace(&mut sizing.queue_size, queue_size);

        self.shared.target.store(threads, Ordering::SeqCst);
        let live = self.live_threads();
        if live < threads {
            self.spawn_workers(&mut sizing, threads - live);
        } else {
            for _ in threads..live {
                // Fails only when all workers are gone already.
                let _ = self.sender.send(Message::Retire);
            }
        }
        debug!(
            threads,
            queue_size, old_queue_size, "password hashing pool resized"
        );
    }

    /// Run `work` on a hashing thread and return its result.
    ///
    /// When the queue is full `on_full` decides: wait for a free slot, or fail
    /// right away with [`PasswordHashError::QueueFull`]. Dropping the returned
    /// future cancels the job: if it did not start yet, it is skipped.
    pub(crate) async fn submit<T, F>(
        &self,
        on_full: PasswordHashingQueueFull,
        work: F,
    ) -> Result<T, PasswordHashError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, PasswordHashError> + Send + 'static,
    {
        if self.live_threads() == 0 && self.ensure_workers() == 0 {
            return Err(PasswordHashError::PoolUnavailable);
        }

        let permit = match on_full {
            PasswordHashingQueueFull::Wait => self
                .slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| PasswordHashError::PoolUnavailable)?,
            reject => match self.slots.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(TryAcquireError::NoPermits) => {
                    METRICS
                        .rejected_total
                        .inc([Label::fixed(behavior_label(reject))]);
                    return Err(PasswordHashError::QueueFull { behavior: reject });
                }
                Err(TryAcquireError::Closed) => return Err(PasswordHashError::PoolUnavailable),
            },
        };

        let (result_tx, result_rx) = oneshot::channel();
        let enqueued = Instant::now();
        METRICS.queue_depth.add(1, []);
        let slot = Slot {
            permit: Some(permit),
            debt: self.debt.clone(),
        };
        let job: Job = Box::new(move || {
            // The job left the queue: free the slot first.
            drop(slot);
            METRICS.queue_depth.add(-1, []);
            METRICS
                .queue_wait
                .record(enqueued.elapsed().as_secs_f64(), []);
            if result_tx.is_closed() {
                // The caller went away while the job was waiting.
                return;
            }
            let _ = result_tx.send(work());
        });

        if self.sender.send(Message::Run(job)).is_err() {
            METRICS.queue_depth.add(-1, []);
            return Err(PasswordHashError::PoolUnavailable);
        }
        // The sender is dropped without a value when the job panicked.
        result_rx
            .await
            .map_err(|_| PasswordHashError::JobPanicked)?
    }
}

fn behavior_label(behavior: PasswordHashingQueueFull) -> &'static str {
    match behavior {
        PasswordHashingQueueFull::TooManyRequests => "too_many_requests",
        PasswordHashingQueueFull::ServiceUnavailable => "service_unavailable",
        PasswordHashingQueueFull::Wait => "wait",
    }
}

/// Take up to `wanted` slots off the debt. Returns how many were taken.
fn take_debt(debt: &AtomicUsize, wanted: usize) -> usize {
    let mut current = debt.load(Ordering::SeqCst);
    loop {
        let taken = current.min(wanted);
        if taken == 0 {
            return 0;
        }
        match debt.compare_exchange(current, current - taken, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return taken,
            Err(actual) => current = actual,
        }
    }
}

/// Give a queue slot back, or take it away when the queue shrank.
fn release_slot(permit: OwnedSemaphorePermit, debt: &AtomicUsize) {
    if take_debt(debt, 1) == 1 {
        permit.forget();
    } else {
        drop(permit);
    }
}

/// Leave the pool when there are more workers than wanted. Returns whether the
/// calling worker has to exit (it is then already uncounted).
fn try_retire(shared: &Shared) -> bool {
    let mut live = shared.live.load(Ordering::SeqCst);
    loop {
        if live <= shared.target.load(Ordering::SeqCst) {
            return false;
        }
        match shared
            .live
            .compare_exchange(live, live - 1, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => return true,
            Err(actual) => live = actual,
        }
    }
}

/// Worker thread body: execute jobs until the pool is dropped or the worker
/// is retired.
fn worker(shared: &Shared) {
    loop {
        // A surplus worker leaves between jobs, without waiting for a retire
        // message to travel through the backlog.
        if try_retire(shared) {
            return;
        }
        // The lock is only held while waiting for the next message, never
        // while running a job.
        let message = shared
            .receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv();
        match message {
            // A panicking job must not take the worker thread down. The
            // caller is notified by the dropped result channel.
            Ok(Message::Run(job)) => {
                if catch_unwind(AssertUnwindSafe(job)).is_err() {
                    error!("a password hashing job panicked");
                }
            }
            // Wakes an idle worker; the check at the top of the loop decides
            // whether it really leaves (the pool may have grown again).
            Ok(Message::Retire) => {}
            Err(_) => break,
        }
    }
    shared.live.fetch_sub(1, Ordering::SeqCst);
}

static POOL: OnceLock<HashingPool> = OnceLock::new();

/// Default number of hashing threads: half of the available parallelism.
fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get() / 2)
        .unwrap_or(1)
        .max(1)
}

/// Thread count and queue size requested by `conf`.
fn configured_size(conf: &Config) -> (usize, usize) {
    (
        conf.identity
            .password_hashing_threads
            .unwrap_or_else(default_threads),
        conf.identity.password_hashing_queue_size,
    )
}

/// Resize the process wide pool to the sizes in `conf`.
///
/// Does nothing while the pool was not used yet: it is created with the
/// configuration of its first use. Call it when the configuration reloads.
pub(crate) fn apply_config(conf: &Config) {
    if let Some(pool) = POOL.get() {
        let (threads, queue_size) = configured_size(conf);
        pool.resize(threads, queue_size);
    }
}

/// Run `work` on the process wide password hashing pool.
///
/// The pool is created on the first call using the thread count and queue size
/// from `conf`. Later changes of these options are applied by [`apply_config`]
/// when the configuration reloads. The full queue behavior is read on every
/// call.
pub(crate) async fn run<T, F>(conf: &Config, work: F) -> Result<T, PasswordHashError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PasswordHashError> + Send + 'static,
{
    let pool = POOL.get_or_init(|| {
        let (threads, queue_size) = configured_size(conf);
        HashingPool::new(threads, queue_size)
    });
    pool.submit(conf.identity.password_hashing_queue_full, work)
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn test_runs_job_and_returns_result() {
        let pool = HashingPool::new(1, 4);
        let res = pool
            .submit(PasswordHashingQueueFull::Wait, || Ok(21 * 2))
            .await
            .unwrap();
        assert_eq!(42, res);
    }

    #[tokio::test]
    async fn test_job_error_is_propagated() {
        let pool = HashingPool::new(1, 4);
        let res: Result<(), _> = pool
            .submit(PasswordHashingQueueFull::Wait, || {
                Err(PasswordHashError::CryptoHash("boom".into()))
            })
            .await;
        assert!(matches!(res, Err(PasswordHashError::CryptoHash(_))));
    }

    type Handle = tokio::task::JoinHandle<Result<(), PasswordHashError>>;

    /// Occupy the only worker of `pool` until the returned sender fires.
    async fn block_worker(pool: &Arc<HashingPool>) -> (mpsc::Sender<()>, Handle) {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let p = pool.clone();
        let running = tokio::spawn(async move {
            p.submit(PasswordHashingQueueFull::Wait, move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            })
            .await
        });
        // The worker is busy now.
        started_rx.await.unwrap();
        (release_tx, running)
    }

    /// Occupy the only worker and the only queue slot of a `HashingPool::new(1,
    /// 1)`. Returns the sender releasing the worker and the pending
    /// submissions.
    async fn saturate(pool: &Arc<HashingPool>) -> (mpsc::Sender<()>, Handle, Handle) {
        let (release_tx, running) = block_worker(pool).await;

        let p = pool.clone();
        let queued =
            tokio::spawn(async move { p.submit(PasswordHashingQueueFull::Wait, || Ok(())).await });
        // Let the queued job take the only slot.
        while pool.slots.available_permits() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        (release_tx, running, queued)
    }

    #[tokio::test]
    async fn test_full_queue_rejects_with_configured_behavior() {
        let pool = Arc::new(HashingPool::new(1, 1));
        let (release, running, queued) = saturate(&pool).await;

        for behavior in [
            PasswordHashingQueueFull::TooManyRequests,
            PasswordHashingQueueFull::ServiceUnavailable,
        ] {
            let res = pool.submit(behavior, || Ok(())).await;
            assert!(
                matches!(res, Err(PasswordHashError::QueueFull { behavior: b }) if b == behavior),
                "unexpected result for {behavior:?}"
            );
        }

        release.send(()).unwrap();
        running.await.unwrap().unwrap();
        queued.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_wait_blocks_until_slot_is_free() {
        let pool = Arc::new(HashingPool::new(1, 1));
        let (release, running, queued) = saturate(&pool).await;

        let p = pool.clone();
        let waiting =
            tokio::spawn(async move { p.submit(PasswordHashingQueueFull::Wait, || Ok(7)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "must wait while the queue is full");

        release.send(()).unwrap();
        running.await.unwrap().unwrap();
        queued.await.unwrap().unwrap();
        assert_eq!(7, waiting.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn test_cancelled_job_is_skipped() {
        let pool = Arc::new(HashingPool::new(1, 4));
        let (release, running) = block_worker(&pool).await;
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        let p = pool.clone();
        let cancelled = tokio::spawn(async move {
            p.submit(PasswordHashingQueueFull::Wait, move || {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancelled.abort();
        let _ = cancelled.await;

        release.send(()).unwrap();
        running.await.unwrap().unwrap();
        // Make sure the worker went through the queue.
        pool.submit(PasswordHashingQueueFull::Wait, || Ok(()))
            .await
            .unwrap();
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Poll `cond` until it holds, failing the test after two seconds.
    async fn wait_until(what: &str, cond: impl Fn() -> bool) {
        for _ in 0..400 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    #[tokio::test]
    async fn test_resize_grows_threads() {
        let pool = Arc::new(HashingPool::new(1, 4));
        let (release, running) = block_worker(&pool).await;

        pool.resize(2, 4);
        assert_eq!(2, pool.live_threads());
        // The new worker serves jobs while the first one is still busy.
        pool.submit(PasswordHashingQueueFull::Wait, || Ok(()))
            .await
            .unwrap();

        release.send(()).unwrap();
        running.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_resize_shrinks_threads() {
        let pool = HashingPool::new(3, 4);
        assert_eq!(3, pool.live_threads());

        pool.resize(1, 4);
        wait_until("surplus workers to exit", || pool.live_threads() == 1).await;
        // The remaining worker still serves jobs.
        let res = pool
            .submit(PasswordHashingQueueFull::Wait, || Ok(5))
            .await
            .unwrap();
        assert_eq!(5, res);
    }

    #[tokio::test]
    async fn test_resize_shrink_then_grow_keeps_workers() {
        let pool = HashingPool::new(3, 4);
        // The retire messages find the pool grown again and are ignored.
        pool.resize(1, 4);
        pool.resize(3, 4);
        pool.submit(PasswordHashingQueueFull::Wait, || Ok(()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(3, pool.live_threads());
    }

    #[tokio::test]
    async fn test_resize_grows_queue() {
        let pool = Arc::new(HashingPool::new(1, 1));
        let (release, running, queued) = saturate(&pool).await;
        assert_eq!(0, pool.slots.available_permits());

        pool.resize(1, 3);
        assert_eq!(2, pool.slots.available_permits());

        release.send(()).unwrap();
        running.await.unwrap().unwrap();
        queued.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_resize_shrinks_queue_with_slots_in_use() {
        let pool = Arc::new(HashingPool::new(1, 3));
        let (release, running) = block_worker(&pool).await;
        let queued: Vec<_> = (0..2)
            .map(|_| {
                let p = pool.clone();
                tokio::spawn(
                    async move { p.submit(PasswordHashingQueueFull::Wait, || Ok(())).await },
                )
            })
            .collect();
        wait_until("jobs to take their slots", || {
            pool.slots.available_permits() == 1
        })
        .await;

        // Two slots go away, only one of them is free right now.
        pool.resize(1, 1);
        assert_eq!(0, pool.slots.available_permits());
        assert_eq!(1, pool.debt.load(Ordering::SeqCst));

        release.send(()).unwrap();
        running.await.unwrap().unwrap();
        for job in queued {
            job.await.unwrap().unwrap();
        }
        // One slot was taken away, the other came back.
        assert_eq!(0, pool.debt.load(Ordering::SeqCst));
        assert_eq!(1, pool.slots.available_permits());
    }

    #[tokio::test]
    async fn test_resize_grow_cancels_debt() {
        let pool = Arc::new(HashingPool::new(1, 2));
        let (release, running) = block_worker(&pool).await;
        let p = pool.clone();
        let queued =
            tokio::spawn(async move { p.submit(PasswordHashingQueueFull::Wait, || Ok(())).await });
        wait_until("job to take its slot", || {
            pool.slots.available_permits() == 1
        })
        .await;
        pool.resize(1, 1);
        assert_eq!(0, pool.slots.available_permits());

        // Growing back must not hand out more slots than the new size.
        pool.resize(1, 2);
        release.send(()).unwrap();
        running.await.unwrap().unwrap();
        queued.await.unwrap().unwrap();
        assert_eq!(0, pool.debt.load(Ordering::SeqCst));
        assert_eq!(2, pool.slots.available_permits());
    }

    #[tokio::test]
    async fn test_panicking_job_does_not_kill_worker() {
        let pool = HashingPool::new(1, 4);
        let res: Result<(), _> = pool
            .submit(PasswordHashingQueueFull::Wait, || panic!("boom"))
            .await;
        assert!(matches!(res, Err(PasswordHashError::JobPanicked)));
        let res = pool
            .submit(PasswordHashingQueueFull::Wait, || Ok(1))
            .await
            .unwrap();
        assert_eq!(1, res);
    }

    #[tokio::test]
    async fn test_absurd_sizes_are_clamped() {
        let pool = HashingPool::new(usize::MAX, usize::MAX);
        assert_eq!(MAX_QUEUE_SIZE, pool.sizing().queue_size);
        assert!(pool.live_threads() <= MAX_THREADS);
        pool.resize(0, 0);
        assert_eq!(1, pool.sizing().queue_size);
        pool.resize(2, usize::MAX);
        assert_eq!(MAX_QUEUE_SIZE, pool.sizing().queue_size);
        assert_eq!(
            4,
            pool.submit(PasswordHashingQueueFull::Wait, || Ok(4))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_submit_restarts_missing_workers() {
        let pool = HashingPool::new(1, 4);
        // Simulate workers that failed to start.
        pool.shared.live.store(0, Ordering::SeqCst);
        let res = pool
            .submit(PasswordHashingQueueFull::Wait, || Ok(9))
            .await
            .unwrap();
        assert_eq!(9, res);
        assert!(pool.live_threads() >= 1);
    }
}
