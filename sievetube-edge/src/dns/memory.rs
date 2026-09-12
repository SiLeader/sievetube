//! In-memory DNS provider with the same conditional semantics as the real
//! adapters. Used by tests and the provider contract suite.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use super::{same_optional, ChangeTicket, DnsError, Observed, RecordSet, RecordType};

#[derive(Clone, Default)]
pub struct MemoryProvider {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    records: Mutex<HashMap<(String, RecordType), Observed>>,
    failures: Mutex<VecDeque<DnsError>>,
    writes: AtomicU64,
    /// When set, changes are reported as Route 53-style tickets that sync on demand
    tracked_changes: Mutex<Option<HashMap<String, bool>>>,
}

impl MemoryProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Report changes as tickets that stay pending until [`MemoryProvider::sync_all`].
    pub fn with_tracked_changes() -> Self {
        let provider = Self::default();
        *provider.inner.tracked_changes.lock().unwrap() = Some(HashMap::new());
        provider
    }

    /// Simulate a change made by another tool.
    pub fn set_external(&self, set: RecordSet) {
        self.records().insert(
            (set.name.clone(), set.record_type),
            Observed {
                set,
                unsupported: None,
            },
        );
    }

    #[allow(dead_code)] // used by provider-specific tests
    pub fn set_unsupported(&self, set: RecordSet, reason: &str) {
        self.records().insert(
            (set.name.clone(), set.record_type),
            Observed {
                set,
                unsupported: Some(reason.to_string()),
            },
        );
    }

    #[allow(dead_code)] // used by provider-specific tests
    pub fn remove_external(&self, name: &str, record_type: RecordType) {
        self.records().remove(&(name.to_string(), record_type));
    }

    pub fn snapshot(&self, name: &str, record_type: RecordType) -> Option<RecordSet> {
        self.records()
            .get(&(name.to_string(), record_type))
            .map(|o| o.set.clone())
    }

    /// Make the next provider call fail with `error`.
    pub fn fail_next(&self, error: DnsError) {
        self.inner
            .failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(error);
    }

    pub fn writes(&self) -> u64 {
        self.inner.writes.load(Ordering::SeqCst)
    }

    pub fn sync_all(&self) {
        if let Some(changes) = self
            .inner
            .tracked_changes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            changes.values_mut().for_each(|synced| *synced = true);
        }
    }

    fn records(&self) -> std::sync::MutexGuard<'_, HashMap<(String, RecordType), Observed>> {
        self.inner
            .records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn take_failure(&self) -> Result<(), DnsError> {
        match self
            .inner
            .failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
        {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub fn get(&self, name: &str, record_type: RecordType) -> Result<Option<Observed>, DnsError> {
        self.take_failure()?;
        Ok(self
            .records()
            .get(&(name.to_string(), record_type))
            .cloned())
    }

    pub fn replace(
        &self,
        name: &str,
        record_type: RecordType,
        expected: Option<&RecordSet>,
        desired: Option<&RecordSet>,
    ) -> Result<ChangeTicket, DnsError> {
        self.take_failure()?;
        let mut records = self.records();
        let key = (name.to_string(), record_type);
        let current = records.get(&key);
        if let Some(reason) = current.and_then(|o| o.unsupported.clone()) {
            return Err(DnsError::Conflict(reason));
        }
        if !same_optional(current.map(|o| &o.set), expected) {
            return Err(DnsError::Conflict(
                "record set changed at the provider".to_string(),
            ));
        }
        match desired {
            Some(set) => {
                let mut stored = set.clone();
                if stored.proxied.is_none() && record_type != RecordType::Txt {
                    stored.proxied = current.and_then(|o| o.set.proxied).or(Some(false));
                }
                records.insert(
                    key,
                    Observed {
                        set: stored,
                        unsupported: None,
                    },
                );
            }
            None => {
                records.remove(&key);
            }
        }
        let write = self.inner.writes.fetch_add(1, Ordering::SeqCst) + 1;
        let mut tracked = self
            .inner
            .tracked_changes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match tracked.as_mut() {
            Some(changes) => {
                let change_id = format!("C{write}");
                changes.insert(change_id.clone(), false);
                Ok(ChangeTicket::Route53 { change_id })
            }
            None => Ok(ChangeTicket::Immediate),
        }
    }

    /// Tracked changes report PENDING on the first poll and INSYNC afterwards.
    pub fn change_synced(&self, change_id: &str) -> bool {
        let mut tracked = self
            .inner
            .tracked_changes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match tracked
            .as_mut()
            .and_then(|changes| changes.get_mut(change_id))
        {
            Some(synced) if *synced => true,
            Some(synced) => {
                *synced = true;
                false
            }
            None => false,
        }
    }
}
