use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Result, bail};
use tokio::sync::Semaphore;

// ──────────────────────────────────────────────────────────────
//  Mutation gate
// ──────────────────────────────────────────────────────────────

/// Controls mutation admission.  Every mutation path (normal DELETE,
/// retry, ReDeleteIfRecreated, finalizer strip, residual cleanup)
/// must acquire a [`MutationPermit`] before calling the Kubernetes API.
///
/// The permit is held through the API call **and** the durable journal
/// checkpoint that follows.  This ensures that when [`close_and_drain`]
/// returns, every admitted mutation has a durable outcome.
pub struct MutationGate {
    open: AtomicBool,
    semaphore: Arc<Semaphore>,
    max_permits: u32,
}

/// RAII guard held through mutation + durable checkpoint.
pub struct MutationPermit {
    _inner: tokio::sync::OwnedSemaphorePermit,
}

impl MutationGate {
    pub fn new(max_concurrent: u32) -> Self {
        Self {
            open: AtomicBool::new(true),
            semaphore: Arc::new(Semaphore::new(max_concurrent as usize)),
            max_permits: max_concurrent,
        }
    }

    /// Acquire a mutation permit.
    ///
    /// Returns `Err` if the gate is closed (pausing / paused).
    /// The permit **must** be held until the durable checkpoint
    /// succeeds so that `close_and_drain` can guarantee all
    /// admitted mutations have durable outcomes.
    pub async fn acquire(&self) -> Result<MutationPermit> {
        // Fast-path rejection
        if !self.open.load(Ordering::SeqCst) {
            bail!("Mutation gate is closed (pausing or paused)");
        }

        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("Semaphore closed"))?;

        // Double-check: gate may have closed between the fast-path
        // check and the semaphore grant.
        if !self.open.load(Ordering::SeqCst) {
            drop(permit);
            bail!("Mutation gate closed during permit acquisition");
        }

        Ok(MutationPermit { _inner: permit })
    }

    /// Close the gate and wait for **all** active permits to drain.
    ///
    /// After this method returns:
    /// - No new permits can be acquired.
    /// - Every previously-admitted mutation has dropped its permit
    ///   (meaning its durable checkpoint completed or failed).
    pub async fn close_and_drain(&self) {
        // 1. Reject new acquires
        self.open.store(false, Ordering::SeqCst);

        // 2. Wait until every outstanding permit is returned.
        //    Acquiring all `max_permits` slots means nothing else holds one.
        let drain = self
            .semaphore
            .acquire_many(self.max_permits)
            .await;
        // Drop immediately — we only needed to block until drained.
        drop(drain);
    }

    /// Re-open the gate (used on resume after Paused).
    pub fn reopen(&self) {
        self.open.store(true, Ordering::SeqCst);
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }
}

// ──────────────────────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn test_acquire_when_open() {
        let gate = MutationGate::new(4);
        let p = gate.acquire().await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn test_acquire_when_closed() {
        let gate = MutationGate::new(4);
        gate.open.store(false, Ordering::SeqCst);
        let p = gate.acquire().await;
        assert!(p.is_err());
    }

    #[tokio::test]
    async fn test_reopen_allows_acquire() {
        let gate = MutationGate::new(4);
        gate.open.store(false, Ordering::SeqCst);
        assert!(gate.acquire().await.is_err());
        gate.reopen();
        assert!(gate.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn test_close_and_drain_waits_for_active_permit() {
        // Shared gate behind Arc so we can move into spawned tasks.
        let gate = Arc::new(MutationGate::new(4));

        // Acquire a permit *before* closing.
        let permit = gate.acquire().await.unwrap();

        let gate2 = gate.clone();
        let drain_handle = tokio::spawn(async move {
            gate2.close_and_drain().await;
        });

        // Drain should not complete yet because `permit` is held.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!drain_handle.is_finished());

        // Drop the permit → drain unblocks.
        drop(permit);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(drain_handle.is_finished());

        // After drain, new acquire must fail.
        assert!(gate.acquire().await.is_err());
    }

    #[tokio::test]
    async fn test_pause_drain_race_no_post_close_mutation() {
        // Scenario:
        //   1. Task A acquires permit (open gate).
        //   2. Task B closes and drains.
        //   3. Task C tries to acquire after close — must fail.
        //   4. Task A drops permit — drain completes.
        //   5. Task C retries — still fails.
        let gate = Arc::new(MutationGate::new(4));

        let permit_a = gate.acquire().await.unwrap();

        let g = gate.clone();
        let drain = tokio::spawn(async move { g.close_and_drain().await });

        // Give drain a moment to flip the flag.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Task C: must fail immediately.
        assert!(
            gate.acquire().await.is_err(),
            "acquire after close_and_drain must fail"
        );

        drop(permit_a);
        drain.await.unwrap();

        // Still closed.
        assert!(gate.acquire().await.is_err());
    }

    #[tokio::test]
    async fn test_double_check_toctou() {
        // Simulate the TOCTOU window: gate is open when checked,
        // but closes before the semaphore grants.
        // We can't perfectly race the real code, but we can verify
        // the double-check catches the close.
        let gate = Arc::new(MutationGate::new(1));

        // Fill the single slot so the next acquire blocks on semaphore.
        let blocker = gate.acquire().await.unwrap();

        let g = gate.clone();
        let acquire_task = tokio::spawn(async move { g.acquire().await });

        // Close while the acquire_task is waiting for the semaphore.
        tokio::time::sleep(Duration::from_millis(10)).await;
        gate.open.store(false, Ordering::SeqCst);

        // Release the blocker → semaphore grants to acquire_task,
        // but the double-check should reject.
        drop(blocker);

        let result = acquire_task.await.unwrap();
        assert!(
            result.is_err(),
            "double-check should reject permit acquired after gate close"
        );
    }
}
