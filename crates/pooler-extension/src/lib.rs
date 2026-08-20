//! A small, supervised boundary for untrusted external inspectors and transforms.
//!
//! Every invocation starts a fresh child process and exchanges one bounded
//! newline-delimited JSON request and response.  The child receives no
//! credentials, inherited environment, or Pooler-owned handles through this
//! API.  A process crash, timeout, cancellation, malformed response, or
//! resource limit is returned as an ordinary request error.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fmt, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::{OwnedSemaphorePermit, Semaphore},
    time,
};
use tokio_util::sync::CancellationToken;
use wasmtime::{
    Config as WasmConfig, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};

/// The protocol version sent to an external process.
pub const PROTOCOL_VERSION: u32 = 1;
/// A conservative default for one request body.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 1024 * 1024;
/// A conservative default for one response line.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// A bounded default invocation timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// A bounded default process RSS allowance where the host exposes RSS data.
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
/// A bounded default process concurrency.
pub const DEFAULT_MAX_CONCURRENCY: usize = 4;
const SANDBOX_COMMAND: &str = "/extension/program";
const SANDBOX_SHELL: &str = "/bin/sh";

/// An operation an extension is allowed to perform.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionOperation {
    /// Read bounded input and return metadata without changing the body.
    Inspect,
    /// Read bounded input and return a replacement body.
    Transform,
}

impl fmt::Display for ExtensionOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Inspect => "inspect",
            Self::Transform => "transform",
        })
    }
}

/// An explicit capability granted to one extension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExtensionCapability {
    /// Permit inspect calls.
    Inspect,
    /// Permit transform calls.
    Transform,
}

impl ExtensionCapability {
    /// Stable configuration and wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Transform => "transform",
        }
    }

    /// Parse a capability declaration.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "inspect" => Some(Self::Inspect),
            "transform" => Some(Self::Transform),
            _ => None,
        }
    }

    const fn operation(self) -> ExtensionOperation {
        match self {
            Self::Inspect => ExtensionOperation::Inspect,
            Self::Transform => ExtensionOperation::Transform,
        }
    }
}

/// Capabilities granted to one extension.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtensionCapabilities(BTreeSet<ExtensionCapability>);

impl ExtensionCapabilities {
    /// Construct capabilities from explicit values.
    #[must_use]
    pub fn from_capabilities(values: impl IntoIterator<Item = ExtensionCapability>) -> Self {
        Self(values.into_iter().collect())
    }

    /// Construct capabilities from configuration spellings.
    pub fn from_names<'a>(values: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut capabilities = BTreeSet::new();
        for value in values {
            let capability = ExtensionCapability::parse(value)
                .ok_or_else(|| format!("unknown extension capability `{value}`"))?;
            if !capabilities.insert(capability) {
                return Err(format!("duplicate extension capability `{value}`"));
            }
        }
        Ok(Self(capabilities))
    }

    /// Whether the operation is explicitly granted.
    #[must_use]
    pub fn allows(&self, operation: ExtensionOperation) -> bool {
        self.0
            .iter()
            .any(|capability| capability.operation() == operation)
    }

    /// Stable list included in the child request.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.0.iter().map(|value| value.as_str()).collect()
    }

    /// Whether no capabilities are granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Resource bounds for one external invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionLimits {
    /// Maximum serialized request size, including protocol metadata.
    pub max_input_bytes: usize,
    /// Maximum serialized response size, including protocol metadata.
    pub max_output_bytes: usize,
    /// Maximum wall-clock invocation duration.
    pub timeout: Duration,
    /// Maximum child RSS where the host exposes `/proc` RSS data.
    pub max_memory_bytes: u64,
    /// Maximum concurrent child processes for this extension.
    pub max_concurrency: usize,
}

impl Default for ExtensionLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            timeout: DEFAULT_TIMEOUT,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
        }
    }
}

impl ExtensionLimits {
    /// Validate bounds before a process can be started.
    pub fn validate(self) -> Result<Self, ExtensionError> {
        if self.max_input_bytes == 0 {
            return Err(ExtensionError::InvalidLimits(
                "max_input_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.max_output_bytes == 0 {
            return Err(ExtensionError::InvalidLimits(
                "max_output_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.timeout.is_zero() {
            return Err(ExtensionError::InvalidLimits(
                "timeout must be greater than zero".to_owned(),
            ));
        }
        if self.max_memory_bytes == 0 {
            return Err(ExtensionError::InvalidLimits(
                "max_memory_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.max_concurrency == 0 {
            return Err(ExtensionError::InvalidLimits(
                "max_concurrency must be greater than zero".to_owned(),
            ));
        }
        Ok(self)
    }
}

/// Immutable executable specification for an external extension.
#[derive(Clone, Debug)]
pub struct ExtensionSpec {
    /// Stable extension ID used by route component references.
    pub id: Arc<str>,
    /// Absolute executable path. Relative command lookup is intentionally not
    /// allowed because a cleared environment must not reintroduce PATH search.
    pub command: PathBuf,
    /// Fixed arguments supplied to every invocation.
    pub args: Vec<OsString>,
    /// Explicit operation grants.
    pub capabilities: ExtensionCapabilities,
    /// Invocation bounds.
    pub limits: ExtensionLimits,
}

impl ExtensionSpec {
    /// Validate and construct an executable specification.
    pub fn new(
        id: impl Into<Arc<str>>,
        command: impl Into<PathBuf>,
        args: impl IntoIterator<Item = OsString>,
        capabilities: ExtensionCapabilities,
        limits: ExtensionLimits,
    ) -> Result<Self, ExtensionError> {
        let command = command.into();
        if !command.is_absolute() {
            return Err(ExtensionError::RelativeCommand(command));
        }
        if command.as_os_str().is_empty() {
            return Err(ExtensionError::EmptyCommand);
        }
        let limits = limits.validate()?;
        if capabilities.is_empty() {
            return Err(ExtensionError::NoCapabilities);
        }
        Ok(Self {
            id: id.into(),
            command,
            args: args.into_iter().collect(),
            capabilities,
            limits,
        })
    }
}

/// Input provided to an extension. It contains no headers, credentials, or
/// handles; callers must deliberately copy any safe routing metadata here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionInput {
    /// Media type of the bounded body.
    pub media_type: String,
    /// Body bytes bounded by [`ExtensionLimits::max_input_bytes`].
    pub body: Vec<u8>,
    /// Non-secret metadata selected by the caller.
    pub metadata: BTreeMap<String, String>,
}

impl ExtensionInput {
    /// Construct an input with no metadata.
    #[must_use]
    pub fn new(media_type: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            media_type: media_type.into(),
            body,
            metadata: BTreeMap::new(),
        }
    }
}

/// Metadata returned by an inspect call.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtensionInspection {
    /// Bounded, non-secret fields emitted by the extension.
    pub metadata: BTreeMap<String, String>,
}

/// Errors crossing the extension boundary.
#[derive(Debug, Error)]
pub enum ExtensionError {
    /// An operation was not granted in configuration.
    #[error("extension `{extension}` is not granted capability `{operation}`")]
    CapabilityDenied {
        /// Extension ID.
        extension: String,
        /// Requested operation.
        operation: ExtensionOperation,
    },
    /// Executable path was relative.
    #[error("extension command `{0}` must be an absolute path")]
    RelativeCommand(PathBuf),
    /// Executable path was empty.
    #[error("extension command cannot be empty")]
    EmptyCommand,
    /// Configuration bounds are invalid.
    #[error("invalid extension limits: {0}")]
    InvalidLimits(String),
    /// No operation grant was configured.
    #[error("extension must grant at least one capability")]
    NoCapabilities,
    /// Request or response exceeded a serialized bound.
    #[error("extension {direction} exceeded the {limit} byte limit")]
    ByteLimit {
        /// Request or response.
        direction: &'static str,
        /// Bound name.
        limit: &'static str,
    },
    /// Child process could not be started.
    #[error("failed to start extension: {0}")]
    Start(#[source] io::Error),
    /// The required Linux sandbox was unavailable or rejected by the host.
    #[error("external extension sandbox is unavailable: {0}")]
    SandboxUnavailable(String),
    /// Child exited unsuccessfully.
    #[error("extension exited unsuccessfully: {status}")]
    Crashed {
        /// Process status description.
        status: String,
    },
    /// Child did not answer before the deadline.
    #[error("extension invocation timed out")]
    Timeout,
    /// Invocation was cancelled by the caller.
    #[error("extension invocation cancelled")]
    Cancelled,
    /// Child output was not valid protocol JSON.
    #[error("invalid extension response: {0}")]
    Protocol(String),
    /// Child exceeded the configured RSS bound.
    #[error("extension exceeded its memory limit")]
    MemoryLimit,
    /// Another invocation could not obtain its bounded process slot.
    #[error("extension concurrency limit reached")]
    Concurrency,
    /// A WASM module could not be compiled or executed under the no-imports
    /// extension contract.
    #[error("WASM extension failed: {0}")]
    Wasm(String),
}

#[derive(Clone, Debug)]
struct Sandbox {
    bwrap: PathBuf,
    setsid: PathBuf,
    kill: PathBuf,
}

impl Sandbox {
    fn discover() -> Result<Self, ExtensionError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(ExtensionError::SandboxUnavailable(
                "the supervised external boundary currently requires Linux bubblewrap".to_owned(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let bwrap = ["/usr/bin/bwrap", "/bin/bwrap"]
                .into_iter()
                .map(PathBuf::from)
                .find(|path| path.is_file())
                .ok_or_else(|| {
                    ExtensionError::SandboxUnavailable(
                        "bubblewrap was not found at a trusted system path".to_owned(),
                    )
                })?;
            let setsid = ["/usr/bin/setsid", "/bin/setsid"]
                .into_iter()
                .map(PathBuf::from)
                .find(|path| path.is_file())
                .ok_or_else(|| {
                    ExtensionError::SandboxUnavailable(
                        "setsid was not found at a trusted system path".to_owned(),
                    )
                })?;
            let kill = ["/usr/bin/kill", "/bin/kill"]
                .into_iter()
                .map(PathBuf::from)
                .find(|path| path.is_file())
                .ok_or_else(|| {
                    ExtensionError::SandboxUnavailable(
                        "the trusted process-group killer was not found".to_owned(),
                    )
                })?;
            let sandbox = Self {
                bwrap,
                setsid,
                kill,
            };
            sandbox.probe()
        }
    }

    #[cfg(target_os = "linux")]
    fn probe(&self) -> Result<Self, ExtensionError> {
        let mut command = std::process::Command::new(&self.setsid);
        command
            .arg(&self.bwrap)
            .args(sandbox_arguments(
                Path::new("/bin/true"),
                &[],
                DEFAULT_MAX_MEMORY_BYTES,
            ))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let status = command.status().map_err(ExtensionError::Start)?;
        if status.success() {
            Ok(self.clone())
        } else {
            Err(ExtensionError::SandboxUnavailable(format!(
                "bubblewrap probe exited with {status}"
            )))
        }
    }
}

fn sandbox_arguments(command: &Path, args: &[OsString], max_memory_bytes: u64) -> Vec<OsString> {
    let mut values = vec![
        OsString::from("--die-with-parent"),
        OsString::from("--new-session"),
        OsString::from("--unshare-all"),
        OsString::from("--unshare-user"),
        OsString::from("--disable-userns"),
        OsString::from("--clearenv"),
        OsString::from("--setenv"),
        OsString::from("PATH"),
        OsString::from("/usr/bin:/bin"),
        OsString::from("--setenv"),
        OsString::from("HOME"),
        OsString::from("/tmp"),
        OsString::from("--uid"),
        OsString::from("65534"),
        OsString::from("--gid"),
        OsString::from("65534"),
        OsString::from("--chdir"),
        OsString::from("/tmp"),
        OsString::from("--cap-drop"),
        OsString::from("ALL"),
        OsString::from("--ro-bind"),
        OsString::from("/usr"),
        OsString::from("/usr"),
        OsString::from("--ro-bind"),
        OsString::from("/bin"),
        OsString::from("/bin"),
        OsString::from("--ro-bind"),
        OsString::from("/lib"),
        OsString::from("/lib"),
        OsString::from("--ro-bind-try"),
        OsString::from("/lib64"),
        OsString::from("/lib64"),
        OsString::from("--proc"),
        OsString::from("/proc"),
        OsString::from("--dev"),
        OsString::from("/dev"),
        OsString::from("--tmpfs"),
        OsString::from("/tmp"),
        OsString::from("--dir"),
        OsString::from("/extension"),
        OsString::from("--ro-bind"),
        command.as_os_str().to_owned(),
        OsString::from(SANDBOX_COMMAND),
        OsString::from("--"),
        OsString::from(SANDBOX_SHELL),
        OsString::from("-c"),
        OsString::from("ulimit -v \"$1\"; shift; exec \"$@\""),
        OsString::from("pooler-extension"),
    ];
    values.push(OsString::from(
        memory_limit_kib(max_memory_bytes).to_string(),
    ));
    values.push(OsString::from(SANDBOX_COMMAND));
    values.extend(args.iter().cloned());
    values
}

fn memory_limit_kib(bytes: u64) -> u64 {
    bytes.saturating_div(1024).max(1)
}

/// A no-host-import WebAssembly extension.
///
/// The module must export `memory` and a `handle(i32, i32) -> i64` function.
/// The host writes the same bounded JSON request used by the process protocol
/// into linear memory at offset 4096. The packed return value contains the
/// output pointer in its low 32 bits and output length in its high 32 bits.
/// No WASI or other host imports are linked, so the module has no filesystem,
/// network, environment, process, or Pooler-memory access.
#[derive(Clone)]
pub struct WasmExtension {
    id: Arc<str>,
    capabilities: ExtensionCapabilities,
    limits: ExtensionLimits,
    engine: Arc<Engine>,
    module: Module,
    slots: Arc<Semaphore>,
}

impl std::fmt::Debug for WasmExtension {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmExtension")
            .field("id", &self.id)
            .field("capabilities", &self.capabilities)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct WasmState {
    limits: StoreLimits,
}

impl WasmExtension {
    /// Compile a no-import module with fuel and linear-memory limits.
    pub fn new(
        id: impl Into<Arc<str>>,
        module_bytes: &[u8],
        capabilities: ExtensionCapabilities,
        limits: ExtensionLimits,
    ) -> Result<Self, ExtensionError> {
        let limits = limits.validate()?;
        if capabilities.is_empty() {
            return Err(ExtensionError::NoCapabilities);
        }
        let mut config = WasmConfig::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine =
            Engine::new(&config).map_err(|error| ExtensionError::Wasm(error.to_string()))?;
        let module = Module::new(&engine, module_bytes)
            .map_err(|error| ExtensionError::Wasm(error.to_string()))?;
        if let Some(import) = module.imports().next() {
            return Err(ExtensionError::Wasm(format!(
                "host imports are disabled (`{}`)",
                import.name()
            )));
        }
        if module.get_export("memory").is_none() || module.get_export("handle").is_none() {
            return Err(ExtensionError::Wasm(
                "module must export memory and handle".to_owned(),
            ));
        }
        Ok(Self {
            id: id.into(),
            capabilities,
            // Epoch interruption is engine-wide. Serializing calls for one
            // module ensures cancelling one invocation cannot trap another.
            slots: Arc::new(Semaphore::new(1)),
            limits,
            engine: Arc::new(engine),
            module,
        })
    }

    /// Invoke the inspect capability.
    pub async fn inspect(
        &self,
        input: ExtensionInput,
        cancellation: CancellationToken,
    ) -> Result<ExtensionInspection, ExtensionError> {
        let response = self
            .invoke(ExtensionOperation::Inspect, input, cancellation)
            .await?;
        Ok(ExtensionInspection {
            metadata: response.metadata,
        })
    }

    /// Invoke the transform capability.
    pub async fn transform(
        &self,
        input: ExtensionInput,
        cancellation: CancellationToken,
    ) -> Result<Vec<u8>, ExtensionError> {
        let response = self
            .invoke(ExtensionOperation::Transform, input, cancellation)
            .await?;
        response
            .body
            .ok_or_else(|| ExtensionError::Protocol("transform response omitted body".to_owned()))
    }

    async fn invoke(
        &self,
        operation: ExtensionOperation,
        input: ExtensionInput,
        cancellation: CancellationToken,
    ) -> Result<WireResponse, ExtensionError> {
        if !self.capabilities.allows(operation) {
            return Err(ExtensionError::CapabilityDenied {
                extension: self.id.to_string(),
                operation,
            });
        }
        let request = WireRequest::from_input_for_limits(
            &self.capabilities,
            operation,
            &input,
            self.limits.max_input_bytes,
        )?;
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|error| ExtensionError::Protocol(error.to_string()))?;
        if request_bytes.len() + 1 > self.limits.max_input_bytes {
            return Err(ExtensionError::ByteLimit {
                direction: "request",
                limit: "max_input_bytes",
            });
        }
        let permit = acquire_slot(Arc::clone(&self.slots), cancellation.clone()).await?;
        let engine = Arc::clone(&self.engine);
        let module = self.module.clone();
        let limits = self.limits;
        let mut task =
            tokio::task::spawn_blocking(move || run_wasm(&engine, &module, request_bytes, limits));
        let result = tokio::select! {
            result = &mut task => match result {
                Ok(result) => result,
                Err(error) => Err(ExtensionError::Wasm(error.to_string())),
            },
            _ = time::sleep(self.limits.timeout) => {
                self.engine.increment_epoch();
                let _ = task.await;
                Err(ExtensionError::Timeout)
            },
            _ = cancellation.cancelled() => {
                self.engine.increment_epoch();
                let _ = task.await;
                Err(ExtensionError::Cancelled)
            },
        };
        drop(permit);
        result
    }
}

fn run_wasm(
    engine: &Engine,
    module: &Module,
    request: Vec<u8>,
    limits: ExtensionLimits,
) -> Result<WireResponse, ExtensionError> {
    let store_limits = StoreLimitsBuilder::new()
        .memory_size(limits.max_memory_bytes as usize)
        .instances(1)
        .tables(1)
        .build();
    let mut store = Store::new(
        engine,
        WasmState {
            limits: store_limits,
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(wasm_fuel_budget(limits.timeout))
        .map_err(|error| ExtensionError::Wasm(error.to_string()))?;
    store.set_epoch_deadline(1);
    let linker = Linker::new(engine);
    let instance = linker
        .instantiate(&mut store, module)
        .map_err(|error| ExtensionError::Wasm(error.to_string()))?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| ExtensionError::Wasm("module memory export is invalid".to_owned()))?;
    let function = instance
        .get_typed_func::<(i32, i32), i64>(&mut store, "handle")
        .map_err(|error| ExtensionError::Wasm(error.to_string()))?;
    let input_offset = 4096_usize;
    memory
        .write(&mut store, input_offset, &request)
        .map_err(|error| ExtensionError::Wasm(error.to_string()))?;
    let packed = function
        .call(
            &mut store,
            (
                i32::try_from(input_offset).map_err(|_| ExtensionError::ByteLimit {
                    direction: "request",
                    limit: "max_input_bytes",
                })?,
                i32::try_from(request.len()).map_err(|_| ExtensionError::ByteLimit {
                    direction: "request",
                    limit: "max_input_bytes",
                })?,
            ),
        )
        .map_err(|error| ExtensionError::Wasm(error.to_string()))?;
    let packed = packed as u64;
    let output_offset = usize::try_from(packed as u32)
        .map_err(|_| ExtensionError::Wasm("invalid output pointer".to_owned()))?;
    let output_length = usize::try_from(packed >> 32)
        .map_err(|_| ExtensionError::Wasm("invalid output length".to_owned()))?;
    if output_length > limits.max_output_bytes {
        return Err(ExtensionError::ByteLimit {
            direction: "response",
            limit: "max_output_bytes",
        });
    }
    let mut output = vec![0_u8; output_length];
    memory
        .read(&store, output_offset, &mut output)
        .map_err(|error| ExtensionError::Wasm(error.to_string()))?;
    parse_response(&output)
}

fn wasm_fuel_budget(timeout: Duration) -> u64 {
    timeout
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
        .saturating_mul(100_000)
        .clamp(100_000, 100_000_000)
}

/// A registry of independently supervised extensions.
#[derive(Clone, Debug, Default)]
pub struct ExtensionRegistry {
    extensions: BTreeMap<Arc<str>, Arc<ExtensionHandle>>,
}

#[derive(Debug)]
enum ExtensionHandle {
    Process(ExternalExtension),
    Wasm(WasmExtension),
}

impl ExtensionRegistry {
    /// Build a registry from validated specifications.
    pub fn from_specs(
        specs: impl IntoIterator<Item = ExtensionSpec>,
    ) -> Result<Self, ExtensionError> {
        let specs = specs.into_iter().collect::<Vec<_>>();
        if specs.is_empty() {
            return Ok(Self::default());
        }
        let sandbox = Arc::new(Sandbox::discover()?);
        let mut extensions = BTreeMap::new();
        for spec in specs {
            if extensions.contains_key(&spec.id) {
                return Err(ExtensionError::Protocol(format!(
                    "duplicate extension `{}`",
                    spec.id
                )));
            }
            extensions.insert(
                spec.id.clone(),
                Arc::new(ExtensionHandle::Process(ExternalExtension::new(
                    spec,
                    Arc::clone(&sandbox),
                ))),
            );
        }
        Ok(Self { extensions })
    }

    /// Build a registry from already compiled, no-import WASM extensions.
    pub fn from_wasm_extensions(
        extensions: impl IntoIterator<Item = WasmExtension>,
    ) -> Result<Self, ExtensionError> {
        let mut registry = Self::default();
        for extension in extensions {
            let id = extension.id.clone();
            if registry.extensions.contains_key(&id) {
                return Err(ExtensionError::Protocol(format!(
                    "duplicate extension `{id}`"
                )));
            }
            registry
                .extensions
                .insert(id, Arc::new(ExtensionHandle::Wasm(extension)));
        }
        Ok(registry)
    }

    /// Merge two independently built registries without allowing ID shadowing.
    pub fn merge(&mut self, other: Self) -> Result<(), ExtensionError> {
        for (id, extension) in other.extensions {
            if self.extensions.insert(id.clone(), extension).is_some() {
                return Err(ExtensionError::Protocol(format!(
                    "duplicate extension `{id}`"
                )));
            }
        }
        Ok(())
    }

    /// Look up an extension by stable ID.
    #[must_use]
    fn get(&self, id: &str) -> Option<Arc<ExtensionHandle>> {
        self.extensions.get(id).cloned()
    }

    /// Invoke an inspect operation.
    pub async fn inspect(
        &self,
        id: &str,
        input: ExtensionInput,
        cancellation: CancellationToken,
    ) -> Result<ExtensionInspection, ExtensionError> {
        let extension = self
            .get(id)
            .ok_or_else(|| ExtensionError::Protocol(format!("unknown extension `{id}`")))?;
        match extension.as_ref() {
            ExtensionHandle::Process(extension) => extension.inspect(input, cancellation).await,
            ExtensionHandle::Wasm(extension) => extension.inspect(input, cancellation).await,
        }
    }

    /// Invoke a transform operation.
    pub async fn transform(
        &self,
        id: &str,
        input: ExtensionInput,
        cancellation: CancellationToken,
    ) -> Result<Vec<u8>, ExtensionError> {
        let extension = self
            .get(id)
            .ok_or_else(|| ExtensionError::Protocol(format!("unknown extension `{id}`")))?;
        match extension.as_ref() {
            ExtensionHandle::Process(extension) => extension.transform(input, cancellation).await,
            ExtensionHandle::Wasm(extension) => extension.transform(input, cancellation).await,
        }
    }
}

/// One independently supervised external executable.
#[derive(Debug)]
pub struct ExternalExtension {
    spec: ExtensionSpec,
    sandbox: Arc<Sandbox>,
    slots: Arc<Semaphore>,
}

impl ExternalExtension {
    fn new(spec: ExtensionSpec, sandbox: Arc<Sandbox>) -> Self {
        let slots = Arc::new(Semaphore::new(spec.limits.max_concurrency));
        Self {
            spec,
            sandbox,
            slots,
        }
    }

    /// Invoke the inspect capability.
    pub async fn inspect(
        &self,
        input: ExtensionInput,
        cancellation: CancellationToken,
    ) -> Result<ExtensionInspection, ExtensionError> {
        let response = self
            .invoke(ExtensionOperation::Inspect, input, cancellation)
            .await?;
        Ok(ExtensionInspection {
            metadata: response.metadata,
        })
    }

    /// Invoke the transform capability.
    pub async fn transform(
        &self,
        input: ExtensionInput,
        cancellation: CancellationToken,
    ) -> Result<Vec<u8>, ExtensionError> {
        let response = self
            .invoke(ExtensionOperation::Transform, input, cancellation)
            .await?;
        response
            .body
            .ok_or_else(|| ExtensionError::Protocol("transform response omitted body".to_owned()))
    }

    async fn invoke(
        &self,
        operation: ExtensionOperation,
        input: ExtensionInput,
        cancellation: CancellationToken,
    ) -> Result<WireResponse, ExtensionError> {
        if !self.spec.capabilities.allows(operation) {
            return Err(ExtensionError::CapabilityDenied {
                extension: self.spec.id.to_string(),
                operation,
            });
        }
        let request = WireRequest::from_input(&self.spec, operation, &input)?;
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|error| ExtensionError::Protocol(error.to_string()))?;
        if request_bytes.len() + 1 > self.spec.limits.max_input_bytes {
            return Err(ExtensionError::ByteLimit {
                direction: "request",
                limit: "max_input_bytes",
            });
        }
        let permit = acquire_slot(Arc::clone(&self.slots), cancellation.clone()).await?;
        let result = self.run_child(operation, request_bytes, cancellation).await;
        drop(permit);
        result
    }

    async fn run_child(
        &self,
        _operation: ExtensionOperation,
        request: Vec<u8>,
        cancellation: CancellationToken,
    ) -> Result<WireResponse, ExtensionError> {
        let sandbox_args = sandbox_arguments(
            &self.spec.command,
            &self.spec.args,
            self.spec.limits.max_memory_bytes,
        );
        let mut command = Command::new(&self.sandbox.setsid);
        command
            .arg(&self.sandbox.bwrap)
            .args(sandbox_args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(ExtensionError::Start)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| ExtensionError::Protocol("extension stdin unavailable".to_owned()))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExtensionError::Protocol("extension stdout unavailable".to_owned()))?;
        let mut request_line = request;
        request_line.push(b'\n');
        let max_output = self.spec.limits.max_output_bytes;
        let timeout = self.spec.limits.timeout;
        let memory_limit = self.spec.limits.max_memory_bytes;

        let exchange = async {
            stdin
                .write_all(&request_line)
                .await
                .map_err(|error| ExtensionError::Protocol(error.to_string()))?;
            stdin
                .shutdown()
                .await
                .map_err(|error| ExtensionError::Protocol(error.to_string()))?;
            let mut output = Vec::with_capacity(max_output.min(8192));
            let mut bounded_stdout = (&mut stdout).take((max_output as u64).saturating_add(1));
            let read = bounded_stdout.read_to_end(&mut output);
            tokio::pin!(read);
            loop {
                tokio::select! {
                    result = &mut read => {
                        result.map_err(|error| ExtensionError::Protocol(error.to_string()))?;
                        break;
                    }
                    _ = time::sleep(Duration::from_millis(20)), if memory_limit > 0 => {
                        if process_tree_memory_bytes(child.id())
                            .is_some_and(|rss| rss > memory_limit)
                        {
                            terminate_child(&mut child, &self.sandbox).await;
                            return Err(ExtensionError::MemoryLimit);
                        }
                    }
                }
            }
            if output.len() > max_output {
                terminate_child(&mut child, &self.sandbox).await;
                return Err(ExtensionError::ByteLimit {
                    direction: "response",
                    limit: "max_output_bytes",
                });
            }
            let status = child
                .wait()
                .await
                .map_err(|error| ExtensionError::Protocol(error.to_string()))?;
            if !status.success() {
                return Err(ExtensionError::Crashed {
                    status: status.to_string(),
                });
            }
            parse_response(&output)
        };

        tokio::select! {
            result = time::timeout(timeout, exchange) => {
                match result {
                    Ok(result) => result,
                    Err(_) => {
                        terminate_child(&mut child, &self.sandbox).await;
                        Err(ExtensionError::Timeout)
                    }
                }
            }
            _ = cancellation.cancelled() => {
                terminate_child(&mut child, &self.sandbox).await;
                Err(ExtensionError::Cancelled)
            }
        }
    }
}

async fn terminate_child(child: &mut Child, sandbox: &Sandbox) {
    if let Some(pid) = child.id() {
        let group = format!("-{pid}");
        let _ = Command::new(&sandbox.kill)
            .arg("-KILL")
            .arg(group)
            .status()
            .await;
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

async fn acquire_slot(
    slots: Arc<Semaphore>,
    cancellation: CancellationToken,
) -> Result<OwnedSemaphorePermit, ExtensionError> {
    tokio::select! {
        result = slots.acquire_owned() => result.map_err(|_| ExtensionError::Concurrency),
        _ = cancellation.cancelled() => Err(ExtensionError::Cancelled),
    }
}

fn parse_response(output: &[u8]) -> Result<WireResponse, ExtensionError> {
    let line = output
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or_else(|| ExtensionError::Protocol("empty response".to_owned()))?;
    if line.is_empty() {
        return Err(ExtensionError::Protocol("empty response".to_owned()));
    }
    let response: WireResponse = serde_json::from_slice(line)
        .map_err(|error| ExtensionError::Protocol(error.to_string()))?;
    if output[line.len()..]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        return Err(ExtensionError::Protocol(
            "response contains more than one JSON value".to_owned(),
        ));
    }
    Ok(response)
}

fn process_tree_memory_bytes(pid: Option<u32>) -> Option<u64> {
    let pid = pid?;
    #[cfg(target_os = "linux")]
    {
        let mut pending = vec![pid];
        let mut seen = BTreeSet::new();
        let mut total = 0_u64;
        while let Some(current) = pending.pop() {
            if !seen.insert(current) {
                continue;
            }
            let status = std::fs::read_to_string(format!("/proc/{current}/status")).ok()?;
            let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
            let value = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
            total = total.checked_add(value.checked_mul(1024)?)?;
            let children =
                std::fs::read_to_string(format!("/proc/{current}/task/{current}/children")).ok()?;
            pending.extend(
                children
                    .split_whitespace()
                    .filter_map(|value| value.parse::<u32>().ok()),
            );
        }
        Some(total)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

#[derive(Debug, Serialize)]
struct WireRequest<'a> {
    protocol: u32,
    operation: ExtensionOperation,
    capabilities: Vec<&'static str>,
    media_type: &'a str,
    body: &'a [u8],
    metadata: &'a BTreeMap<String, String>,
}

impl<'a> WireRequest<'a> {
    fn from_input(
        spec: &'a ExtensionSpec,
        operation: ExtensionOperation,
        input: &'a ExtensionInput,
    ) -> Result<Self, ExtensionError> {
        Self::from_input_for_limits(
            &spec.capabilities,
            operation,
            input,
            spec.limits.max_input_bytes,
        )
    }

    fn from_input_for_limits(
        capabilities: &'a ExtensionCapabilities,
        operation: ExtensionOperation,
        input: &'a ExtensionInput,
        max_input_bytes: usize,
    ) -> Result<Self, ExtensionError> {
        if input.body.len() > max_input_bytes {
            return Err(ExtensionError::ByteLimit {
                direction: "request",
                limit: "max_input_bytes",
            });
        }
        Ok(Self {
            protocol: PROTOCOL_VERSION,
            operation,
            capabilities: capabilities.names(),
            media_type: &input.media_type,
            body: &input.body,
            metadata: &input.metadata,
        })
    }
}

#[derive(Debug, Deserialize)]
struct WireResponse {
    #[serde(default)]
    body: Option<Vec<u8>>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{env, fs};
    use tempfile::tempdir;

    fn script(contents: &str) -> PathBuf {
        script_named("extension.sh", contents)
    }

    fn script_named(name: &str, contents: &str) -> PathBuf {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join(name);
        fs::write(&path, format!("#!/bin/sh\n{contents}\n")).expect("script");
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&path).expect("metadata").permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&path, permissions).expect("permissions");
        }
        let path = path.clone();
        // Keep the directory alive through the process by leaking only this
        // test fixture. The production runtime never owns test temp paths.
        std::mem::forget(directory);
        path
    }

    fn spec(command: PathBuf, capabilities: &[ExtensionCapability]) -> ExtensionSpec {
        ExtensionSpec::new(
            "test",
            command,
            [],
            ExtensionCapabilities::from_capabilities(capabilities.iter().copied()),
            ExtensionLimits {
                max_input_bytes: 64 * 1024,
                max_output_bytes: 1024,
                timeout: Duration::from_millis(250),
                max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
                max_concurrency: 1,
            },
        )
        .expect("valid spec")
    }

    fn registry(specs: impl IntoIterator<Item = ExtensionSpec>) -> Option<ExtensionRegistry> {
        match ExtensionRegistry::from_specs(specs) {
            Ok(registry) => Some(registry),
            Err(ExtensionError::SandboxUnavailable(reason)) => {
                eprintln!("process extension test skipped: sandbox unavailable ({reason})");
                None
            }
            Err(error) => panic!("registry: {error}"),
        }
    }

    #[test]
    fn process_extensions_fail_closed_without_the_required_sandbox() {
        let result = Sandbox::discover();
        if let Err(ExtensionError::SandboxUnavailable(reason)) = result {
            assert!(!reason.trim().is_empty());
        }
    }

    #[tokio::test]
    async fn transform_is_bounded_and_receives_only_explicit_context() {
        let secret_name = "POOLER_EXTENSION_TEST_SECRET";
        env::set_var(secret_name, "must-not-cross-boundary");
        let command = script(
            "read line; [ -z \"$POOLER_EXTENSION_TEST_SECRET\" ] || exit 11; printf '%s\\n' '{\"body\":[111,107],\"metadata\":{}}'",
        );
        let Some(registry) = registry([spec(command, &[ExtensionCapability::Transform])]) else {
            env::remove_var(secret_name);
            return;
        };
        let result = registry
            .transform(
                "test",
                ExtensionInput::new("application/json", vec![1, 2, 3]),
                CancellationToken::new(),
            )
            .await
            .expect("transform");
        assert_eq!(result, b"ok");
        env::remove_var(secret_name);
    }

    #[tokio::test]
    async fn capability_denial_happens_before_spawn() {
        let command = script("exit 99");
        let Some(registry) = registry([spec(command, &[ExtensionCapability::Inspect])]) else {
            return;
        };
        let error = registry
            .transform(
                "test",
                ExtensionInput::new("application/json", vec![]),
                CancellationToken::new(),
            )
            .await
            .expect_err("denied operation");
        assert!(matches!(error, ExtensionError::CapabilityDenied { .. }));
    }

    #[tokio::test]
    async fn crashed_extension_is_anordinary_error() {
        let command = script("exit 17");
        let Some(registry) = registry([spec(command, &[ExtensionCapability::Transform])]) else {
            return;
        };
        let error = registry
            .transform(
                "test",
                ExtensionInput::new("application/json", vec![]),
                CancellationToken::new(),
            )
            .await
            .expect_err("crash");
        assert!(matches!(error, ExtensionError::Crashed { .. }));
    }

    #[tokio::test]
    async fn hung_extension_is_killed_at_the_deadline() {
        let command = script("while :; do :; done");
        let Some(registry) = registry([spec(command, &[ExtensionCapability::Transform])]) else {
            return;
        };
        let error = registry
            .transform(
                "test",
                ExtensionInput::new("application/json", vec![]),
                CancellationToken::new(),
            )
            .await
            .expect_err("timeout");
        assert!(matches!(error, ExtensionError::Timeout), "{error:?}");
    }

    #[tokio::test]
    async fn excessive_output_is_killed_and_bounded() {
        let command = script("read line; head -c 4096 /dev/zero");
        let mut extension = spec(command, &[ExtensionCapability::Transform]);
        extension.limits = ExtensionLimits {
            max_output_bytes: 32,
            ..extension.limits
        };
        let Some(registry) = registry([extension]) else {
            return;
        };
        let error = registry
            .transform(
                "test",
                ExtensionInput::new("application/json", vec![]),
                CancellationToken::new(),
            )
            .await
            .expect_err("output bound");
        assert!(matches!(error, ExtensionError::ByteLimit { .. }));
    }

    #[tokio::test]
    async fn cancellation_kills_the_child() {
        let marker = format!("pooler-extension-descendant-{}", std::process::id());
        let command = script_named(
            &format!("{marker}.sh"),
            &format!("read line; (while :; do :; done) & while :; do :; done # {marker}"),
        );
        let Some(registry) = registry([spec(command, &[ExtensionCapability::Transform])]) else {
            return;
        };
        let cancellation = CancellationToken::new();
        let task = tokio::spawn({
            let cancellation = cancellation.clone();
            async move {
                registry
                    .transform(
                        "test",
                        ExtensionInput::new("application/json", vec![]),
                        cancellation,
                    )
                    .await
            }
        });
        time::sleep(Duration::from_millis(20)).await;
        cancellation.cancel();
        let error = task.await.expect("task").expect_err("cancelled");
        assert!(matches!(error, ExtensionError::Cancelled));
        time::sleep(Duration::from_millis(50)).await;
        assert!(!process_command_lines_contain(&marker));
    }

    #[tokio::test]
    async fn process_sandbox_hides_host_filesystem_and_network() {
        let command = script(
            "read line; test ! -e /home && test ! -e /workspace && ! grep -q '^default' /proc/net/route && printf '%s\\n' '{\"body\":[111,107],\"metadata\":{}}'",
        );
        let Some(registry) = registry([spec(command, &[ExtensionCapability::Transform])]) else {
            return;
        };
        let result = registry
            .transform(
                "test",
                ExtensionInput::new("application/json", vec![]),
                CancellationToken::new(),
            )
            .await
            .expect("sandbox isolation");
        assert_eq!(result, b"ok");
    }

    fn process_command_lines_contain(marker: &str) -> bool {
        let Ok(entries) = fs::read_dir("/proc") else {
            return false;
        };
        entries.flatten().any(|entry| {
            let name = entry.file_name();
            let Ok(name) = name.into_string() else {
                return false;
            };
            if !name.chars().all(|character| character.is_ascii_digit()) {
                return false;
            }
            fs::read(format!("/proc/{name}/cmdline"))
                .ok()
                .is_some_and(|command| String::from_utf8_lossy(&command).contains(marker))
        })
    }

    #[tokio::test]
    async fn wasm_transform_and_inspect_are_bounded_and_import_free() {
        let module = br#"(module
          (memory (export "memory") 1)
          (data (i32.const 0) "{\"body\":[111,107],\"metadata\":{}}")
          (func (export "handle") (param i32 i32) (result i64)
            i64.const 137438953472)
        )"#;
        let extension = WasmExtension::new(
            "wasm",
            module,
            ExtensionCapabilities::from_capabilities([
                ExtensionCapability::Inspect,
                ExtensionCapability::Transform,
            ]),
            ExtensionLimits::default(),
        )
        .expect("WASM module compiles");
        let body = extension
            .transform(
                ExtensionInput::new("application/json", vec![1, 2]),
                CancellationToken::new(),
            )
            .await
            .expect("WASM transform");
        assert_eq!(body, b"ok");
        let inspection = extension
            .inspect(
                ExtensionInput::new("application/json", vec![1, 2]),
                CancellationToken::new(),
            )
            .await
            .expect("WASM inspect");
        assert!(inspection.metadata.is_empty());

        let imported = br#"(module
          (import "env" "read" (func))
        )"#;
        let error = WasmExtension::new(
            "imported",
            imported,
            ExtensionCapabilities::from_capabilities([ExtensionCapability::Inspect]),
            ExtensionLimits::default(),
        )
        .expect_err("imports must be denied");
        assert!(matches!(error, ExtensionError::Wasm(_)));
    }

    #[tokio::test]
    async fn wasm_fuel_and_memory_exhaustion_are_isolated_errors() {
        let loop_module = br#"(module
          (memory (export "memory") 1)
          (func (export "handle") (param i32 i32) (result i64)
            (loop $spin br $spin)
            i64.const 0)
        )"#;
        let looping = WasmExtension::new(
            "loop",
            loop_module,
            ExtensionCapabilities::from_capabilities([ExtensionCapability::Transform]),
            ExtensionLimits {
                timeout: Duration::from_millis(100),
                ..ExtensionLimits::default()
            },
        )
        .expect("loop module compiles");
        let error = looping
            .transform(
                ExtensionInput::new("application/json", vec![]),
                CancellationToken::new(),
            )
            .await
            .expect_err("fuel exhaustion");
        assert!(matches!(error, ExtensionError::Wasm(_)));

        let memory_module = br#"(module
          (memory (export "memory") 1)
          (func (export "handle") (param i32 i32) (result i64)
            i32.const 10000
            memory.grow
            drop
            unreachable
            i64.const 0)
        )"#;
        let memory = WasmExtension::new(
            "memory",
            memory_module,
            ExtensionCapabilities::from_capabilities([ExtensionCapability::Transform]),
            ExtensionLimits {
                max_memory_bytes: 64 * 1024,
                ..ExtensionLimits::default()
            },
        )
        .expect("memory module compiles");
        let error = memory
            .transform(
                ExtensionInput::new("application/json", vec![]),
                CancellationToken::new(),
            )
            .await
            .expect_err("memory exhaustion");
        assert!(matches!(error, ExtensionError::Wasm(_)));
    }

    #[tokio::test]
    async fn wasm_cancellation_interrupts_the_blocking_execution() {
        let module = br#"(module
          (memory (export "memory") 1)
          (func (export "handle") (param i32 i32) (result i64)
            (loop $spin br $spin)
            i64.const 0)
        )"#;
        let extension = WasmExtension::new(
            "cancel",
            module,
            ExtensionCapabilities::from_capabilities([ExtensionCapability::Transform]),
            ExtensionLimits {
                timeout: Duration::from_secs(10),
                ..ExtensionLimits::default()
            },
        )
        .expect("loop module compiles");
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            trigger.cancel();
        });
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            extension.transform(
                ExtensionInput::new("application/json", vec![]),
                cancellation,
            ),
        )
        .await
        .expect("cancelled execution stops")
        .expect_err("cancellation is reported");
        assert!(matches!(error, ExtensionError::Cancelled));
    }
}
