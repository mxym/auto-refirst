static int helper(int x) { return (x * 7) ^ 0x55; }
__attribute__((export_name("check_flag"))) int check_flag(int x) { return helper(x) == 0x1234; }
const char marker[] = "AUTO_REFIRST_WASM_FLAG_PATH";
