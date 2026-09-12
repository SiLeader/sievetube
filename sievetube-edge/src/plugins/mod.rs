//! WebAssembly policy plugins.
//!
//! # ABI version 1
//!
//! A plugin is a core WebAssembly module that
//! * has **no imports** (no WASI or host functions, hence no file, environment or
//!   network access),
//! * exports `memory`,
//! * exports `sievetube_abi_version() -> i32` returning `1`,
//! * exports `sievetube_alloc(len: i32) -> i32` returning a pointer to `len` writable bytes,
//! * exports `sievetube_evaluate(ptr: i32, len: i32) -> i32`.
//!
//! For each request the Edge writes the request context as UTF-8 JSON
//! `{"tenant_id","hostname","protocol","client_ip","method","path"}` into memory
//! obtained from `sievetube_alloc` and calls `sievetube_evaluate`, which returns
//! `0` (allow) or `1` (deny). The output is this single code, so its size is fixed.
//!
//! Every call runs in a fresh store with a memory limit, a fuel budget and a
//! wall-clock deadline. A trap, exhausted fuel, a timeout, exceeding the memory
//! limit or any other return value fails the request (503) without affecting the
//! Edge, other plugins' state or the built-in rules evaluated before plugins.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use serde::Serialize;
use tokio::sync::Semaphore;
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder, Trap};

use sievetube_common::hostname;

use crate::config::PluginConfig;
use crate::policy::RequestContext;

pub const ABI_VERSION: i32 = 1;
const EPOCH_TICK: Duration = Duration::from_millis(1);
const MAX_INPUT_BYTES: usize = 16 * 1024;
const REQUIRED_EXPORTS: [&str; 4] = [
    "memory",
    "sievetube_abi_version",
    "sievetube_alloc",
    "sievetube_evaluate",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginFailure {
    Trap,
    OutOfFuel,
    Timeout,
    MemoryLimit,
    InvalidOutput,
    Busy,
    InputTooLarge,
}

impl PluginFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            PluginFailure::Trap => "trap",
            PluginFailure::OutOfFuel => "out_of_fuel",
            PluginFailure::Timeout => "timeout",
            PluginFailure::MemoryLimit => "memory_limit",
            PluginFailure::InvalidOutput => "invalid_output",
            PluginFailure::Busy => "busy",
            PluginFailure::InputTooLarge => "input_too_large",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginVerdict {
    Allow,
    Deny {
        plugin: String,
    },
    Failed {
        plugin: String,
        failure: PluginFailure,
    },
}

/// Shared engine with fuel metering and epoch interruption. A background thread
/// advances the epoch every millisecond to enforce per-call deadlines.
fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(256 * 1024);
        let engine = Engine::new(&config).expect("wasmtime engine configuration is valid");
        let ticker = engine.clone();
        std::thread::Builder::new()
            .name("sievetube-wasm-epoch".to_string())
            .spawn(move || loop {
                std::thread::sleep(EPOCH_TICK);
                ticker.increment_epoch();
            })
            .expect("spawn wasm epoch thread");
        engine
    })
}

/// Compiled modules keyed by SHA-256, so that switching back to a previous
/// configuration does not recompile.
#[derive(Default)]
pub struct ModuleCache {
    modules: Mutex<HashMap<String, Module>>,
}

impl ModuleCache {
    fn get_or_compile(&self, digest: &str, bytes: &[u8]) -> anyhow::Result<Module> {
        let mut modules = self.modules.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(module) = modules.get(digest) {
            return Ok(module.clone());
        }
        let module =
            Module::new(engine(), bytes).map_err(|e| anyhow!("invalid WebAssembly module: {e}"))?;
        modules.insert(digest.to_string(), module.clone());
        Ok(module)
    }
}

struct LoadedPlugin {
    name: String,
    module: Module,
    applies_to: Vec<String>,
    max_memory_bytes: usize,
    fuel: u64,
    timeout_ticks: u64,
    permits: Arc<Semaphore>,
}

#[derive(Serialize)]
struct PluginInput<'a> {
    tenant_id: &'a str,
    hostname: &'a str,
    protocol: String,
    client_ip: String,
    method: &'a str,
    path: &'a str,
}

/// A request context serialized for the plugins it applies to, so that the
/// modules can be run away from the async runtime.
pub struct PluginJob {
    hostname: String,
    input: Vec<u8>,
}

/// The plugins of one policy configuration, evaluated in order.
#[derive(Default)]
pub struct PluginSet {
    plugins: Vec<LoadedPlugin>,
}

impl std::fmt::Debug for PluginSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginSet")
            .field(
                "plugins",
                &self.plugins.iter().map(|p| &p.name).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl PluginSet {
    /// Load and verify every plugin. Any error rejects the whole set, so the
    /// caller can keep the previous one.
    pub fn load(configs: &[PluginConfig], cache: &ModuleCache) -> anyhow::Result<Self> {
        let mut plugins = Vec::with_capacity(configs.len());
        for cfg in configs {
            let bytes = std::fs::read(&cfg.path)
                .with_context(|| format!("plugin {}: cannot read {}", cfg.name, cfg.path))?;
            let digest = sha256_hex(&bytes);
            if !digest.eq_ignore_ascii_case(cfg.sha256.trim()) {
                bail!(
                    "plugin {}: SHA-256 mismatch (configured {}, file {digest})",
                    cfg.name,
                    cfg.sha256
                );
            }
            let module = cache
                .get_or_compile(&digest, &bytes)
                .with_context(|| format!("plugin {}", cfg.name))?;
            verify_exports(&module).with_context(|| format!("plugin {}", cfg.name))?;
            let applies_to = cfg
                .applies_to
                .iter()
                .map(|p| hostname::normalize_hostname_pattern(p))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("plugin {}: invalid applies_to: {e}", cfg.name))?;
            let plugin = LoadedPlugin {
                name: cfg.name.clone(),
                module,
                applies_to,
                max_memory_bytes: cfg.max_memory_bytes,
                fuel: cfg.fuel,
                timeout_ticks: cfg.timeout_ms.max(1),
                permits: Arc::new(Semaphore::new(cfg.max_concurrent)),
            };
            match plugin.invoke(|store, instance| {
                instance
                    .get_typed_func::<(), i32>(&mut *store, "sievetube_abi_version")?
                    .call(&mut *store, ())
            }) {
                Ok(ABI_VERSION) => {}
                Ok(other) => bail!(
                    "plugin {}: unsupported ABI version {other} (expected {ABI_VERSION})",
                    cfg.name
                ),
                Err(failure) => bail!(
                    "plugin {}: ABI version check failed: {}",
                    cfg.name,
                    failure.as_str()
                ),
            }
            plugins.push(plugin);
        }
        Ok(PluginSet { plugins })
    }

    /// Serialize the request for the plugins that apply to it, or `None` when no
    /// plugin does. Cheap, so it can run on the caller's thread.
    pub fn prepare(&self, ctx: &RequestContext<'_>) -> Option<PluginJob> {
        if !self.plugins.iter().any(|p| p.applies(ctx.hostname)) {
            return None;
        }
        Some(PluginJob {
            hostname: ctx.hostname.to_string(),
            input: serde_json::to_vec(&PluginInput {
                tenant_id: ctx.tenant_id,
                hostname: ctx.hostname,
                protocol: ctx.protocol.to_string(),
                client_ip: ctx.client_ip.to_string(),
                method: ctx.method,
                path: ctx.path,
            })
            .expect("request context serializes"),
        })
    }

    /// Run the applicable plugins. Every call is CPU work with a wall-clock
    /// deadline, so an async caller has to run this on a blocking thread.
    pub fn evaluate_prepared(&self, job: &PluginJob) -> PluginVerdict {
        for plugin in self.plugins.iter().filter(|p| p.applies(&job.hostname)) {
            match plugin.evaluate(&job.input) {
                Ok(0) => continue,
                Ok(1) => {
                    return PluginVerdict::Deny {
                        plugin: plugin.name.clone(),
                    }
                }
                Ok(_) => {
                    return PluginVerdict::Failed {
                        plugin: plugin.name.clone(),
                        failure: PluginFailure::InvalidOutput,
                    }
                }
                Err(failure) => {
                    return PluginVerdict::Failed {
                        plugin: plugin.name.clone(),
                        failure,
                    }
                }
            }
        }
        PluginVerdict::Allow
    }

    /// Prepare and evaluate on the current thread.
    #[cfg(test)]
    pub fn evaluate(&self, ctx: &RequestContext<'_>) -> PluginVerdict {
        match self.prepare(ctx) {
            Some(job) => self.evaluate_prepared(&job),
            None => PluginVerdict::Allow,
        }
    }
}

impl LoadedPlugin {
    fn applies(&self, hostname: &str) -> bool {
        self.applies_to.is_empty()
            || self
                .applies_to
                .iter()
                .any(|pattern| hostname::matches_pattern(pattern, hostname))
    }

    fn evaluate(&self, input: &[u8]) -> Result<i32, PluginFailure> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(PluginFailure::InputTooLarge);
        }
        self.invoke(|store, instance| {
            let memory = instance
                .get_memory(&mut *store, "memory")
                .ok_or_else(|| wasmtime::Error::msg("missing memory export"))?;
            let alloc = instance.get_typed_func::<i32, i32>(&mut *store, "sievetube_alloc")?;
            let evaluate =
                instance.get_typed_func::<(i32, i32), i32>(&mut *store, "sievetube_evaluate")?;
            let len = input.len() as i32;
            let ptr = alloc.call(&mut *store, len)?;
            memory.write(&mut *store, ptr as u32 as usize, input)?;
            evaluate.call(&mut *store, (ptr, len))
        })
    }

    /// Run `f` against a fresh instance with this plugin's limits.
    fn invoke(
        &self,
        f: impl FnOnce(&mut Store<StoreLimits>, &Instance) -> wasmtime::Result<i32>,
    ) -> Result<i32, PluginFailure> {
        let Ok(_permit) = self.permits.try_acquire() else {
            return Err(PluginFailure::Busy);
        };
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.max_memory_bytes)
            .instances(1)
            .memories(1)
            .tables(4)
            .table_elements(10_000)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(engine(), limits);
        store.limiter(|limits| limits);
        store.set_fuel(self.fuel).map_err(|_| PluginFailure::Trap)?;
        store.set_epoch_deadline(self.timeout_ticks);
        store.epoch_deadline_trap();

        let result = Instance::new(&mut store, &self.module, &[])
            .and_then(|instance| f(&mut store, &instance));
        result.map_err(|error| {
            let failure = classify(&error);
            tracing::debug!(plugin = %self.name, failure = failure.as_str(), error = %error, "plugin call failed");
            failure
        })
    }
}

fn classify(error: &wasmtime::Error) -> PluginFailure {
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => PluginFailure::OutOfFuel,
        Some(Trap::Interrupt) => PluginFailure::Timeout,
        Some(_) => PluginFailure::Trap,
        None => {
            let text = format!("{error:#}").to_ascii_lowercase();
            if text.contains("memory")
                && (text.contains("grow") || text.contains("limit") || text.contains("exceed"))
            {
                PluginFailure::MemoryLimit
            } else {
                PluginFailure::Trap
            }
        }
    }
}

fn verify_exports(module: &Module) -> anyhow::Result<()> {
    if let Some(import) = module.imports().next() {
        bail!(
            "imports are not allowed (found {}::{})",
            import.module(),
            import.name()
        );
    }
    for export in REQUIRED_EXPORTS {
        if module.get_export(export).is_none() {
            bail!("missing export {export}");
        }
    }
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
pub mod test_modules {
    //! WAT sources for plugin tests.

    pub fn module(abi_version: i32, evaluate_body: &str, extra: &str) -> String {
        format!(
            r#"(module
  {extra}
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "sievetube_abi_version") (result i32) (i32.const {abi_version}))
  (func (export "sievetube_alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $ptr))
  (func (export "sievetube_evaluate") (param $ptr i32) (param $len i32) (result i32)
    {evaluate_body}))"#
        )
    }

    pub fn allow_all() -> String {
        module(1, "(i32.const 0)", "")
    }

    /// Deny when the request context contains `/admin`.
    pub fn deny_admin_paths() -> String {
        let byte_at = |offset: i32, value: u8| {
            format!("(i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const {offset}))) (i32.const {value}))")
        };
        let matches = b"/admin"
            .iter()
            .enumerate()
            .map(|(offset, b)| byte_at(offset as i32, *b))
            .reduce(|acc, next| format!("(i32.and {acc} {next})"))
            .unwrap();
        module(
            1,
            &format!(
                r#"(local $i i32) (local $end i32)
    (local.set $i (local.get $ptr))
    (local.set $end (i32.sub (i32.add (local.get $ptr) (local.get $len)) (i32.const 6)))
    (block $done
      (loop $scan
        (br_if $done (i32.gt_s (local.get $i) (local.get $end)))
        (if {matches} (then (return (i32.const 1))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))
    (i32.const 0)"#
            ),
            "",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_modules::*;
    use super::*;
    use sievetube_common::config::Protocol;
    use std::path::PathBuf;

    fn write_module(source: &str) -> (PathBuf, String) {
        let path =
            std::env::temp_dir().join(format!("sievetube-plugin-{}.wat", uuid::Uuid::new_v4()));
        std::fs::write(&path, source).unwrap();
        (path, sha256_hex(source.as_bytes()))
    }

    fn config(name: &str, source: &str) -> PluginConfig {
        let (path, sha256) = write_module(source);
        PluginConfig {
            name: name.to_string(),
            path: path.display().to_string(),
            sha256,
            applies_to: Vec::new(),
            max_memory_bytes: 2 * 1024 * 1024,
            fuel: 5_000_000,
            timeout_ms: 1000,
            max_concurrent: 16,
        }
    }

    fn ctx<'a>(hostname: &'a str, path: &'a str) -> RequestContext<'a> {
        RequestContext {
            tenant_id: "tenant",
            hostname,
            protocol: Protocol::Http,
            client_ip: "192.0.2.1".parse().unwrap(),
            method: "GET",
            path,
        }
    }

    fn load(configs: &[PluginConfig]) -> anyhow::Result<PluginSet> {
        PluginSet::load(configs, &ModuleCache::default())
    }

    #[test]
    fn plugins_receive_the_request_context() {
        let set = load(&[config("admin", &deny_admin_paths())]).unwrap();
        assert_eq!(
            set.evaluate(&ctx("a.test", "/public")),
            PluginVerdict::Allow
        );
        assert_eq!(
            set.evaluate(&ctx("a.test", "/admin/users")),
            PluginVerdict::Deny {
                plugin: "admin".into()
            }
        );
    }

    #[test]
    fn applies_to_limits_plugins_to_hostnames() {
        let mut cfg = config("deny", &module(1, "(i32.const 1)", ""));
        cfg.applies_to = vec!["*.strict.test".into()];
        let set = load(&[cfg, config("allow", &allow_all())]).unwrap();
        assert_eq!(
            set.evaluate(&ctx("api.strict.test", "/")),
            PluginVerdict::Deny {
                plugin: "deny".into()
            }
        );
        assert_eq!(set.evaluate(&ctx("other.test", "/")), PluginVerdict::Allow);
    }

    #[test]
    fn runaway_plugins_are_stopped() {
        let infinite = module(1, "(loop $forever (br $forever)) (i32.const 0)", "");

        let fuel_limited = load(&[config("spin", &infinite)]).unwrap();
        assert_eq!(
            fuel_limited.evaluate(&ctx("a.test", "/")),
            PluginVerdict::Failed {
                plugin: "spin".into(),
                failure: PluginFailure::OutOfFuel
            }
        );

        let mut timed = config("spin-timeout", &infinite);
        timed.fuel = u64::MAX / 2;
        timed.timeout_ms = 20;
        let started = std::time::Instant::now();
        let set = load(&[timed]).unwrap();
        assert_eq!(
            set.evaluate(&ctx("a.test", "/")),
            PluginVerdict::Failed {
                plugin: "spin-timeout".into(),
                failure: PluginFailure::Timeout
            }
        );
        assert!(started.elapsed() < Duration::from_secs(2));

        let hog = module(1, "(drop (memory.grow (i32.const 1000))) (i32.const 0)", "");
        let set = load(&[config("hog", &hog)]).unwrap();
        assert!(matches!(
            set.evaluate(&ctx("a.test", "/")),
            PluginVerdict::Failed {
                failure: PluginFailure::MemoryLimit | PluginFailure::Trap,
                ..
            }
        ));

        let invalid = load(&[config("seven", &module(1, "(i32.const 7)", ""))]).unwrap();
        assert_eq!(
            invalid.evaluate(&ctx("a.test", "/")),
            PluginVerdict::Failed {
                plugin: "seven".into(),
                failure: PluginFailure::InvalidOutput
            }
        );

        let crash = load(&[config("crash", &module(1, "(unreachable)", ""))]).unwrap();
        assert!(matches!(
            crash.evaluate(&ctx("a.test", "/")),
            PluginVerdict::Failed {
                failure: PluginFailure::Trap,
                ..
            }
        ));

        // The failures above did not poison later calls.
        let set = load(&[config("allow", &allow_all())]).unwrap();
        assert_eq!(set.evaluate(&ctx("a.test", "/")), PluginVerdict::Allow);
    }

    #[test]
    fn unsafe_or_mismatched_modules_are_rejected() {
        let with_import = module(
            1,
            "(i32.const 0)",
            r#"(import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))"#,
        );
        let err = load(&[config("io", &with_import)]).unwrap_err();
        assert!(
            format!("{err:#}").contains("imports are not allowed"),
            "{err:#}"
        );

        let err = load(&[config("v2", &module(2, "(i32.const 0)", ""))]).unwrap_err();
        assert!(format!("{err:#}").contains("ABI version"), "{err:#}");

        let mut tampered = config("tampered", &allow_all());
        tampered.sha256 = "00".repeat(32);
        let err = load(&[tampered]).unwrap_err();
        assert!(format!("{err:#}").contains("SHA-256 mismatch"), "{err:#}");

        let err =
            load(&[config("partial", "(module (memory (export \"memory\") 1))")]).unwrap_err();
        assert!(format!("{err:#}").contains("missing export"), "{err:#}");
    }

    #[test]
    fn concurrency_limit_fails_fast() {
        let mut cfg = config("single", &allow_all());
        cfg.max_concurrent = 1;
        let set = load(&[cfg]).unwrap();
        let _held = set.plugins[0].permits.try_acquire().unwrap();
        assert_eq!(
            set.evaluate(&ctx("a.test", "/")),
            PluginVerdict::Failed {
                plugin: "single".into(),
                failure: PluginFailure::Busy
            }
        );
    }

    #[test]
    fn module_cache_reuses_compiled_modules() {
        let cache = ModuleCache::default();
        let cfg = config("allow", &allow_all());
        PluginSet::load(std::slice::from_ref(&cfg), &cache).unwrap();
        PluginSet::load(std::slice::from_ref(&cfg), &cache).unwrap();
        assert_eq!(cache.modules.lock().unwrap().len(), 1);
    }
}
