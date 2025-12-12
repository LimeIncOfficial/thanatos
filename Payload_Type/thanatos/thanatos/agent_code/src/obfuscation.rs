//! Control flow obfuscation module.
//!
//! This module provides techniques to obfuscate the control flow of the agent:
//! - Opaque predicates (conditions that always evaluate to a known value)
//! - Dead code insertion
//! - Control flow flattening helpers
//! - Junk code generation
//!
//! These techniques make static analysis and reverse engineering more difficult.
//!
//! Detectable telemetry generated:
//! - Unusual code patterns visible in memory dumps
//! - Complex CFG graphs during analysis

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global counter for opaque predicates
static OPAQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Opaque predicate that always returns true
///
/// Uses mathematical properties that the compiler cannot optimize away.
#[inline(never)]
pub fn opaque_true() -> bool {
    let x = OPAQUE_COUNTER.fetch_add(1, Ordering::SeqCst);
    // (x * x) is always >= 0, so this is always true
    // But the compiler can't prove this at compile time with atomic operations
    (x.wrapping_mul(x)) >= 0 || black_box(false)
}

/// Opaque predicate that always returns false
#[inline(never)]
pub fn opaque_false() -> bool {
    let x = OPAQUE_COUNTER.fetch_add(1, Ordering::SeqCst);
    // This is always false but hard to prove statically
    let y = black_box(x);
    y != y // Always false (NaN check trick doesn't apply to integers)
}

/// Opaque predicate using modular arithmetic
#[inline(never)]
pub fn opaque_mod_true() -> bool {
    let x = OPAQUE_COUNTER.fetch_add(7, Ordering::SeqCst);
    // x^2 mod 4 is always 0 or 1 for any integer x
    // Therefore x^2 mod 4 < 4 is always true
    (x.wrapping_mul(x) % 4) < 4
}

/// Generate junk computation that does nothing useful
/// but adds complexity to analysis
#[inline(never)]
pub fn junk_computation() {
    let mut x = black_box(0x1337u64);
    for _ in 0..black_box(3) {
        x = x.wrapping_mul(0x5851F42D4C957F2D);
        x = x.wrapping_add(0x14057B7EF767814F);
        x ^= x >> 33;
    }
    black_box(x);
}

/// Delay execution with obfuscated loop
/// This is harder to detect than a simple sleep
#[inline(never)]
pub fn obfuscated_delay(iterations: u32) {
    let mut counter = black_box(0u64);
    let target = black_box(iterations as u64);

    while counter < target {
        // Mix of operations to prevent optimization
        counter = counter.wrapping_add(1);
        if opaque_true() {
            black_box(counter);
        }
        if opaque_false() {
            // Dead code - never executed
            counter = 0;
        }
    }
}

/// Macro for inserting opaque predicate guards
///
/// Usage:
/// ```ignore
/// opaque_guard! {
///     // Your sensitive code here
///     do_sensitive_operation();
/// }
/// ```
#[macro_export]
macro_rules! opaque_guard {
    ($($code:tt)*) => {
        if $crate::obfuscation::opaque_true() {
            $($code)*
        } else {
            // Dead branch - compiler can't prove it's never taken
            $crate::obfuscation::junk_computation();
        }
    };
}

/// Macro for control flow flattening
///
/// Converts a sequence of operations into a state machine,
/// making control flow analysis more difficult.
#[macro_export]
macro_rules! flatten_control_flow {
    ($($state:expr => $code:block),+ $(,)?) => {{
        let mut current_state = 0u32;
        let mut iterations = 0u32;
        const MAX_ITERATIONS: u32 = 1000;

        loop {
            if iterations > MAX_ITERATIONS {
                break;
            }
            iterations += 1;

            // Add junk between state transitions
            if $crate::obfuscation::opaque_true() {
                std::hint::black_box(current_state);
            }

            match current_state {
                $($state => {
                    $code
                    current_state += 1;
                }),+
                _ => break,
            }
        }
    }};
}

/// State machine based execution for control flow obfuscation
pub struct FlattenedExecutor<T> {
    state: u32,
    result: Option<T>,
    operations: Vec<Box<dyn FnOnce() -> Option<T>>>,
}

impl<T> FlattenedExecutor<T> {
    /// Create a new flattened executor
    pub fn new() -> Self {
        Self {
            state: 0,
            result: None,
            operations: Vec::new(),
        }
    }

    /// Add an operation to the executor
    pub fn add_op<F: FnOnce() -> Option<T> + 'static>(&mut self, op: F) {
        self.operations.push(Box::new(op));
    }

    /// Execute all operations with flattened control flow
    pub fn execute(mut self) -> Option<T> {
        let op_count = self.operations.len() as u32;
        let mut ops: Vec<_> = self.operations.drain(..).collect();

        while self.state < op_count {
            // Insert junk computation
            junk_computation();

            // Opaque predicate check
            if opaque_true() {
                let idx = self.state as usize;
                if idx < ops.len() {
                    // Execute in "random" order based on state
                    // (actually sequential, but harder to analyze)
                    if let Some(result) = (ops.remove(0))() {
                        self.result = Some(result);
                    }
                }
            }

            self.state += 1;
        }

        self.result
    }
}

impl<T> Default for FlattenedExecutor<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Insert dead code blocks that are never executed
/// but add complexity to CFG analysis
#[inline(never)]
pub fn dead_code_block_1() {
    // This function is never called but exists in the binary
    let x = black_box(42u64);
    let y = black_box(x.wrapping_mul(0xDEADBEEF));
    let _ = black_box(y.rotate_left(13));
}

#[inline(never)]
pub fn dead_code_block_2() {
    let mut data = [0u8; 64];
    for i in 0..64 {
        data[i] = black_box((i * 7) as u8);
    }
    black_box(data);
}

#[inline(never)]
pub fn dead_code_block_3() {
    let s = black_box("never_executed");
    let _ = black_box(s.len());
}

/// String obfuscation helper using XOR
/// Runtime deobfuscation to avoid static string analysis
pub struct XorString {
    data: Vec<u8>,
    key: u8,
}

impl XorString {
    /// Create a new XOR-obfuscated string
    pub fn new(s: &str, key: u8) -> Self {
        let data: Vec<u8> = s.bytes().map(|b| b ^ key).collect();
        Self { data, key }
    }

    /// Decode the string at runtime
    pub fn decode(&self) -> String {
        let decoded: Vec<u8> = self.data.iter().map(|b| b ^ self.key).collect();
        String::from_utf8_lossy(&decoded).to_string()
    }
}

/// Anti-disassembly technique using overlapping instructions
/// (Note: This is architecture-specific and may not work as intended
/// in all cases due to Rust's compilation)
#[inline(never)]
pub fn anti_disasm_block() {
    // Insert bytes that confuse linear disassemblers
    unsafe {
        std::arch::asm!(
            "jmp 2f",
            ".byte 0xE8", // Looks like start of CALL instruction
            "2:",
            options(nomem, nostack),
        );
    }
}

/// Insert timing check to detect single-stepping debuggers
#[inline(never)]
pub fn timing_check() -> bool {
    use std::time::Instant;

    let start = Instant::now();

    // Simple operation that should be fast
    junk_computation();

    let elapsed = start.elapsed().as_millis();

    // If this takes more than 100ms, we might be debugged
    // (single-stepping would make this very slow)
    elapsed < 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opaque_predicates() {
        // Opaque true should always be true
        for _ in 0..100 {
            assert!(opaque_true());
        }

        // Opaque false should always be false
        for _ in 0..100 {
            assert!(!opaque_false());
        }

        // Opaque mod should always be true
        for _ in 0..100 {
            assert!(opaque_mod_true());
        }
    }

    #[test]
    fn test_xor_string() {
        let original = "test string";
        let xor = XorString::new(original, 0x42);
        assert_eq!(xor.decode(), original);
    }
}
