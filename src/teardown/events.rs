use std::sync::atomic::{AtomicU64, Ordering};

/// Non-blocking state change notifier.
///
/// Uses tokio::sync::watch with a monotonic counter. The counter is the
/// "wake-up hint" — consumers read the latest counter value, then inspect
/// RuntimeStateStore for the actual state. Event = hint, State = truth.
///
/// The sender never blocks even if no receiver is listening or if the
/// receiver is slow. This guarantees that mutation/reconciliation in the
/// executor is never stalled by UI/event consumer backpressure.
pub struct EventNotifier {
    tx: tokio::sync::watch::Sender<u64>,
    counter: AtomicU64,
}

impl EventNotifier {
    pub fn new() -> Self {
        let (tx, _rx) = tokio::sync::watch::channel(0u64);
        Self {
            tx,
            counter: AtomicU64::new(0),
        }
    }

    /// Notify all subscribers that state has changed.
    /// Non-blocking: if no subscriber exists, this is a no-op.
    pub fn notify(&self) {
        let val = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        // send() only fails if all receivers are dropped — that's fine
        let _ = self.tx.send(val);
    }

    /// Create a new subscriber that receives wake-up hints.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notifier_non_blocking_no_subscriber() {
        // Notifying with no subscriber must not panic or block
        let notifier = EventNotifier::new();
        notifier.notify();
        notifier.notify();
        // No assertion needed — just verifying it doesn't panic
    }

    #[tokio::test]
    async fn test_notifier_subscriber_receives_latest() {
        let notifier = EventNotifier::new();
        let mut rx = notifier.subscribe();

        notifier.notify();
        notifier.notify();
        notifier.notify();

        // changed() waits for a new value different from last seen
        rx.changed().await.unwrap();
        let val = *rx.borrow();
        // Should see the latest counter, not necessarily every intermediate
        assert!(val >= 1);
    }

    #[tokio::test]
    async fn test_notifier_backpressure_does_not_block_sender() {
        let notifier = EventNotifier::new();
        let _rx = notifier.subscribe(); // hold receiver but don't read

        // Send many notifications — must not block
        for _ in 0..1000 {
            notifier.notify();
        }
        // If we got here, backpressure didn't block
    }
}
