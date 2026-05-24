use ebpfkit::compiler::{compile_character_class, compile_literal_search};
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_compile_literal_search_doesnt_panic(s in "\\PC{0,1000}") {
        let bytes = s.as_bytes();
        let result = compile_literal_search(bytes);
        assert!(result.is_ok() || result.is_err(), "GAP FINDING: compile_literal_search panicked");
    }

    #[test]
    fn prop_compile_character_class_doesnt_panic(s in "[a-zA-Z0-9]{0,50}") {
        let result = compile_character_class(s.as_bytes());
        assert!(result.is_ok() || result.is_err(), "GAP FINDING: compile_character_class panicked");
    }
}
