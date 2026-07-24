#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::fs::File;
use std::io::BufRead;
use std::io::Write;

use fd_lock::RwLock;
use nyks_protocol::triton_vm::config::CacheDecision;
use nyks_protocol::triton_vm::config::ENV_VAR_LDE_CACHE;
use nyks_protocol::triton_vm::config::ENV_VAR_LDE_CACHE_NO_CACHE;
use nyks_protocol::triton_vm::config::ENV_VAR_LDE_CACHE_WITH_CACHE;
use nyks_protocol::triton_vm::config::overwrite_lde_trace_caching_to;
use nyks_protocol::triton_vm::prelude::Program;
use nyks_protocol::triton_vm::proof::Claim;
use nyks_protocol::triton_vm::proof::Proof;
use nyks_protocol::triton_vm::stark::Stark;
use nyks_protocol::triton_vm::vm::NonDeterminism;
use nyks_protocol::triton_vm::vm::VM;
use nyks_prover::PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE;
use nyks_prover::env::TritonVmEnvVars;
use thread_priority::ThreadPriority;
use thread_priority::set_current_thread_priority;

#[cfg(feature = "mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn set_environment_variables(env_vars: &[(String, String)]) {
    // Set environment variables for this spawned process only, does not apply
    // globally. Documentation of `set_var` shows it's for the currently
    // running process only.
    // This is only intended to set two environment variables: TVM_LDE_TRACE and
    // RAYON_NUM_THREADS, depending on the padded height of the algebraic
    // execution trace.
    for (key, value) in env_vars {
        eprintln!("Setting env variable for Triton VM: {key}={value}");

        // SAFETY:
        // - "The exact requirement is: you must ensure that there are no
        //   other threads concurrently writing or reading(!) the
        //   environment through functions or global variables other than
        //   the ones in this module." At this place, this program is
        //   single-threaded. Generation of algebraic execution trace is
        //   done, and proving hasn't started yet.
        unsafe {
            std::env::set_var(key, value);
        }

        // In case Triton VM has already made the cache decision prior to
        // the environment variable being set here, we override it through
        // a publicly exposed function. This override ensures that the Triton
        // VM configuration agrees with the environment variable.
        if key == ENV_VAR_LDE_CACHE {
            let value = value.to_ascii_lowercase();
            let value = value.as_str();
            let decision = if value == ENV_VAR_LDE_CACHE_WITH_CACHE {
                Some(CacheDecision::Cache)
            } else if value == ENV_VAR_LDE_CACHE_NO_CACHE {
                Some(CacheDecision::NoCache)
            } else {
                None
            };

            if let Some(d) = decision {
                eprintln!("TRACE: overwriting cache lde trace to: {d:?}");
                overwrite_lde_trace_caching_to(d);
            }
        }
    }
}

fn execute(
    claim: Claim,
    program: Program,
    non_determinism: NonDeterminism,
    max_log2_padded_height: Option<u8>,
    env_vars: TritonVmEnvVars,
) -> Proof {
    let stark: Stark = Stark::default();

    let (aet, _) = VM::trace_execution(program, (&claim.input).into(), non_determinism).unwrap();
    let log2_padded_height = aet.padded_height().ilog2() as u8;

    // Use std-err for logging purposes since spawner (caller) doesn't get the
    // log outputs but can capture std-err.
    eprintln!("actual log2 padded height for proof: {log2_padded_height}");

    if max_log2_padded_height.is_some_and(|max| log2_padded_height > max) {
        eprintln!(
            "Canceling prover because padded height exceeds max value of {}",
            max_log2_padded_height.unwrap()
        );
        // Exit with error code indicating 1) AET padded height too big, and 2)
        // the log2 padded height. Guaranteed to be in the range [200-232].
        std::process::exit(
            PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE + i32::from(log2_padded_height),
        );
    }

    let env_vars = env_vars
        .get(&log2_padded_height)
        .map(|x| x.to_owned())
        .unwrap_or_default();

    set_environment_variables(&env_vars);

    stark.prove(&claim, &aet).unwrap()
}

fn main() {
    // run with a low priority so other processes can remain responsive.
    //
    // TODO: we could accept a thread-priority cli param (0..100) and
    //       pass it with ThreadPriority::CrossPlatform(x).
    set_current_thread_priority(ThreadPriority::Min).unwrap();

    // Acquire the exclusive prover lock before doing any work. Only one
    // prover process should run at a time; concurrent callers block here until
    // the current holder exits and its file descriptor is closed.
    let lock_path = std::env::temp_dir().join(".proverlock");
    let lock_file = File::create(&lock_path).unwrap();
    let mut prover_lock = RwLock::new(lock_file);
    let _prover_guard = prover_lock.write().unwrap();

    let stdin = std::io::stdin();
    let mut iterator = stdin.lock().lines();
    let claim: Claim = serde_json::from_str(&iterator.next().unwrap().unwrap()).unwrap();
    let program: Program = serde_json::from_str(&iterator.next().unwrap().unwrap()).unwrap();
    let non_determinism: NonDeterminism =
        serde_json::from_str(&iterator.next().unwrap().unwrap()).unwrap();
    let max_log2_padded_height: Option<u8> =
        serde_json::from_str(&iterator.next().unwrap().unwrap()).unwrap();
    let env_variables: TritonVmEnvVars =
        serde_json::from_str(&iterator.next().unwrap().unwrap()).unwrap();

    let proof = execute(
        claim,
        program,
        non_determinism,
        max_log2_padded_height,
        env_variables,
    );
    eprintln!("triton-vm: completed proof");

    let as_bytes = bincode::serialize(&proof).unwrap();
    let mut stdout = std::io::stdout();
    stdout.write_all(&as_bytes).unwrap();
    stdout.flush().unwrap();
}
