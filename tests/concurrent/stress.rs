use ebpfkit::assembler::format_program;
use ebpfkit::compiler::compile_literal_search;
use std::thread;

#[test]
fn concurrent_compile_and_format_stress_test() {
    let mut handles = vec![];

    // Spawn 32 threads hammering the identical API
    for i in 0..32 {
        let handle = thread::spawn(move || {
            let pattern = format!("adversarial_pattern_match_{}", i);
            for _ in 0..100 {
                let prog_result = compile_literal_search(pattern.as_bytes());

                assert!(
                    prog_result.is_ok(),
                    "GAP FINDING: Thread failed to compile pattern {}",
                    i
                );

                let prog = prog_result.unwrap();
                let formatted = format_program(&prog);

                assert!(
                    !formatted.is_empty(),
                    "GAP FINDING: Thread formatted an empty program!"
                );

                // Assert it successfully outputs standard instructions
                assert!(
                    formatted.contains("exit"),
                    "GAP FINDING: Thread formatted program does not contain 'exit'!"
                );
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let res = handle.join();
        assert!(
            res.is_ok(),
            "GAP FINDING: A thread panicked during concurrent compilation!"
        );
    }
}
