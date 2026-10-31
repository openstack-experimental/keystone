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
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, PoisonError};
use std::time::Instant;

use openstack_keystone_config::{Config, PasswordHashingQueueFull};
use openstack_keystone_telemetry::metrics::{
    self, CounterVec, HistogramVec, Label, UpDownCounterVec,
};
use tokio::sync::{Semaphore, TryAcquireError, oneshot};
use tracing::{debug, error};

use super::PasswordHashError;

type Job = Box<dyn FnOnce() + Send + 'static>;

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

/// A fixed set of OS threads executing password hashing jobs.
pub(crate) struct HashingPool {
    /// Job queue feeding the worker threads. `None` when no worker could be
    /// started.
    sender: Option<Sender<Job>>,
    /// One permit per free slot in the queue.
    slots: Arc<Semaphore>,
}

impl HashingPool {
    /// Start `threads` workers (at least 1) with room for `queue_size` (at
    /// least 1) jobs waiting for them.
    pub(crate) fn new(threads: usize, queue_size: usize) -> Self {
        let threads = threads.max(1);
        let (sender, receiver) = channel::<Job>();
        let receiver = Arc::new(Mutex::new(receiver));

        let mut started = 0usize;
        for index in 0..threads {
            let receiver = receiver.clone();
            match std::thread::Builder::new()
                .name(format!("pwd-hash-{index}"))
                .spawn(move || worker(&receiver))
            {
                Ok(_) => started += 1,
                Err(err) => error!(%err, "failed to start a password hashing thread"),
            }
        }
        debug!(
            threads = started,
            queue_size, "password hashing pool started"
        );

        Self {
            sender: (started > 0).then_some(sender),
            slots: Arc::new(Semaphore::new(queue_size.max(1))),
        }
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
        let sender = self
            .sender
            .as_ref()
            .ok_or(PasswordHashError::PoolUnavailable)?;

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
        let job: Job = Box::new(move || {
            // The job left the queue: free the slot first.
            drop(permit);
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

        if sender.send(job).is_err() {
            METRICS.queue_depth.add(-1, []);
            return Err(PasswordHashError::PoolUnavailable);
        }
        // The sender is dropped without a value when the job panicked.
        result_rx
            .await
            .map_err(|_| PasswordHashError::PoolUnavailable)?
    }
}

fn behavior_label(behavior: PasswordHashingQueueFull) -> &'static str {
    match behavior {
        PasswordHashingQueueFull::TooManyRequests => "too_many_requests",
        PasswordHashingQueueFull::ServiceUnavailable => "service_unavailable",
        PasswordHashingQueueFull::Wait => "wait",
    }
}

/// Worker thread body: execute jobs until the pool is dropped.
fn worker(receiver: &Mutex<Receiver<Job>>) {
    loop {
        // The lock is only held while waiting for the next job, never while
        // running it.
        let job = receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv();
        match job {
            // A panicking job must not take the worker thread down. The
            // caller is notified by the dropped result channel.
            Ok(job) => {
                if catch_unwind(AssertUnwindSafe(job)).is_err() {
                    error!("a password hashing job panicked");
                }
            }
            Err(_) => break,
        }
    }
}

static POOL: OnceLock<HashingPool> = OnceLock::new();

/// Default number of hashing threads: half of the available parallelism.
fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get() / 2)
        .unwrap_or(1)
        .max(1)
}

/// Run `work` on the process wide password hashing pool.
///
/// The pool is created on the first call using the thread count and queue size
/// from `conf`; later changes of these two options do not apply until the
/// process is restarted. The full queue behavior is read on every call.
pub(crate) async fn run<T, F>(conf: &Config, work: F) -> Result<T, PasswordHashError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PasswordHashError> + Send + 'static,
{
    let pool = POOL.get_or_init(|| {
        HashingPool::new(
            conf.identity
                .password_hashing_threads
                .unwrap_or_else(default_threads),
            conf.identity.password_hashing_queue_size,
        )
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

    #[tokio::test]
    async fn test_panicking_job_does_not_kill_worker() {
        let pool = HashingPool::new(1, 4);
        let res: Result<(), _> = pool
            .submit(PasswordHashingQueueFull::Wait, || panic!("boom"))
            .await;
        assert!(matches!(res, Err(PasswordHashError::PoolUnavailable)));
        let res = pool
            .submit(PasswordHashingQueueFull::Wait, || Ok(1))
            .await
            .unwrap();
        assert_eq!(1, res);
    }
}
