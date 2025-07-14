MAX_TOOL_CALL_RESULT_LENGTH = 40 * 1024
MAX_POV_LENGTH = 2097152

# OSS-Fuzz constants
DEFAULT_LANGUAGE = 'c++'
DEFAULT_SANITIZER = 'address'
DEFAULT_ARCHITECTURE = 'x86_64'
DEFAULT_ENGINE = 'libfuzzer'
DEFAULT_LIB_FUZZING_ENGINE = '/usr/lib/libFuzzingEngine.a'
LANGUAGES = [
    'c',
    'c++',
    'go',
    'javascript',
    'jvm',
    'python',
    'rust',
    'swift',
    'ruby',
]
LANGUAGES_WITH_COVERAGE_SUPPORT = [
    'c', 'c++', 'go', 'jvm', 'python', 'rust', 'swift', 'javascript', 'ruby'
]
SANITIZERS = [
    'address',
    'none',
    'memory',
    'undefined',
    'thread',
    'coverage',
    'introspector',
    'hwaddress',
]
SANITIZER_VARS = [s + "_OPTIONS" for s in ["ASAN", "MSAN", "UBSAN", "LSAN", "TSAN"]]
ARCHITECTURES = ['i386', 'x86_64', 'aarch64']
ENGINES = ['libfuzzer', 'afl', 'honggfuzz', 'centipede', 'none', 'wycheproof']
DEFAULT_FUZZER_DIRS = ["aflplusplus", "fuzztest", "libfuzzer", "honggfuzz", "libprotobuf-mutator"]

# https://github.com/aixcc-finals/example-crs-architecture/tree/main/docs/source_language_determination
# based on running their tool against ALL extensions for ALL langs in
# https://github.com/github-linguist/linguist/blob/main/lib/linguist/languages.yml
C_EXTENSIONS = {'.ixx', '.ipp', '.ino', '.h++', '.cxx', '.cats', '.inl', '.h', '.cc', '.hxx', '.c', '.cpp', '.inc', '.idc', '.tpp', '.hpp', '.cp', '.c++', '.tcc', '.cppm', '.txx', '.re', '.hh'} # '.h.in' excluded
JAVA_EXTENSIONS = {'.java', '.jav', '.jsh'}
SOURCE_CODE_EXTENSIONS = C_EXTENSIONS | JAVA_EXTENSIONS