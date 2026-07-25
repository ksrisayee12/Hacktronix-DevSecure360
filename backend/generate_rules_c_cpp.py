from rule_writer import write_rule

C_SOURCES = [
    "gets(", "fgets(", "scanf(", "fscanf(", "sscanf(", "read(", "recv(", "recvfrom(", "getenv(", "argv["
]

CPP_SOURCES = C_SOURCES # Similar sources for C++

def gen_c_cpp_rules():
    # C Rules
    write_rule(
        "c", "c_buffer_overflow", "Buffer Overflow", "High", "CWE-119", "A03:2021-Injection", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Tentative",
        "Buffer Overflow via unsafe string functions",
        "User input is copied into a fixed-size buffer using unsafe functions that do not check bounds. Attackers can overflow the buffer to overwrite memory, potentially gaining Remote Code Execution.",
        C_SOURCES,
        ["strcpy(", "strcat(", "sprintf(", "vsprintf(", "gets("],
        ["strncpy(", "strncat(", "snprintf(", "fgets("],
        "Use bounds-checking string functions from the C standard library. Never use gets() under any circumstances.\n\nUNSAFE:\n  strcpy(dest, argv[1]);\n\nSAFE:\n  strncpy(dest, argv[1], sizeof(dest) - 1);\n  dest[sizeof(dest) - 1] = '\\0';"
    )

    write_rule(
        "c", "c_format_string", "Format String", "High", "CWE-134", "A03:2021-Injection", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Format String Vulnerability via printf family",
        "User input is passed directly as the format string argument to a printf-family function. Attackers can inject format specifiers (like %x or %n) to read from or write to arbitrary memory locations.",
        C_SOURCES,
        ["printf(", "fprintf(", "sprintf(", "snprintf(", "syslog(", "err(", "warn("],
        [],
        "Never pass user input as the format string. Always use a static format string and pass the user input as an argument.\n\nUNSAFE:\n  printf(argv[1]);\n\nSAFE:\n  printf(\"%s\", argv[1]);"
    )

    write_rule(
        "c", "c_cmdi", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via system or exec",
        "User input is passed directly to system() or popen(). Attackers can append shell commands to gain Remote Code Execution on the server.",
        C_SOURCES,
        ["system(", "popen(", "execl(", "execlp(", "execle(", "execv(", "execvp(", "execve("],
        [],
        "Avoid using system() which spawns a shell. Use exec() family functions and pass arguments as an array of strings, properly sanitizing any inputs.\n\nUNSAFE:\n  system(command_string);\n\nSAFE:\n  execvp(\"ping\", args);"
    )

    write_rule(
        "c", "c_integer_overflow", "Integer Overflow", "High", "CWE-190", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "Tentative",
        "Integer Overflow or Wraparound",
        "User-controlled integer values are used in arithmetic operations without bounds checking. Attackers can trigger overflows or underflows, leading to logic errors or buffer overflows during memory allocation.",
        C_SOURCES,
        ["malloc(", "calloc(", "realloc(", "memcpy(", "memmove("],
        [],
        "Validate integer inputs before performing arithmetic operations, especially if the result is used for memory allocation. Check against INT_MAX or UINT_MAX to prevent wrapping.\n\nUNSAFE:\n  size_t total = count * sizeof(struct obj);\n  void *ptr = malloc(total);\n\nSAFE:\n  if (count > MAX_COUNT) return ERROR;\n  size_t total = count * sizeof(struct obj);"
    )

    write_rule(
        "c", "c_use_after_free", "Use After Free", "Critical", "CWE-416", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Tentative",
        "Use After Free",
        "A pointer is used after the memory it points to has been freed. Attackers can control the freed memory region, potentially leading to arbitrary code execution if function pointers or vtables are manipulated.",
        C_SOURCES,
        ["free("],
        [],
        "Set pointers to NULL immediately after freeing them. Avoid using dangling pointers.\n\nUNSAFE:\n  free(ptr);\n  // ... later ...\n  ptr->value = 10;\n\nSAFE:\n  free(ptr);\n  ptr = NULL;"
    )

    # C++ Rules
    write_rule(
        "cpp", "cpp_buffer_overflow", "Buffer Overflow", "High", "CWE-119", "A03:2021-Injection", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Tentative",
        "Buffer Overflow via legacy C functions",
        "User input is copied into a buffer using legacy C functions in a C++ program. Attackers can overflow the buffer to overwrite memory.",
        CPP_SOURCES,
        ["strcpy(", "strcat(", "sprintf(", "vsprintf(", "gets("],
        ["std::string", "std::vector<char>", "std::array", "std::copy_n("],
        "Avoid using legacy C string functions (like strcpy) and raw char arrays in C++. Use safe C++ alternatives like std::string or std::vector which manage memory automatically.\n\nUNSAFE:\n  char buf[256];\n  strcpy(buf, argv[1]);\n\nSAFE:\n  std::string buf = argv[1];"
    )

    write_rule(
        "cpp", "cpp_format_string", "Format String", "High", "CWE-134", "A03:2021-Injection", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Format String Vulnerability via printf family",
        "User input is passed directly as the format string argument to a printf-family function in C++.",
        CPP_SOURCES,
        ["printf(", "fprintf(", "sprintf(", "snprintf(", "syslog(", "err(", "warn("],
        ["std::cout <<"],
        "Never pass user input as the format string. Always use a static format string, or use C++ streams (std::cout) which are not vulnerable to format string attacks.\n\nUNSAFE:\n  printf(argv[1]);\n\nSAFE:\n  std::cout << argv[1];"
    )

    write_rule(
        "cpp", "cpp_cmdi", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via system",
        "User input is passed directly to system() or popen(). Attackers can append shell commands to gain Remote Code Execution on the server.",
        CPP_SOURCES,
        ["system(", "popen(", "execl(", "execlp(", "execle(", "execv(", "execvp(", "execve("],
        [],
        "Avoid using system() which spawns a shell. Use exec() family functions and pass arguments as an array of strings.\n\nUNSAFE:\n  system(command_string);\n\nSAFE:\n  execvp(\"ping\", args);"
    )

    write_rule(
        "cpp", "cpp_deserialization", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via Boost or Cereal",
        "Untrusted data is deserialized using Boost.Serialization or Cereal. Attackers can execute arbitrary code upon deserialization if object types are manipulated.",
        CPP_SOURCES,
        ["boost::archive::text_iarchive", "boost::archive::binary_iarchive", "cereal::JSONInputArchive", "cereal::BinaryInputArchive"],
        [],
        "Do not deserialize untrusted data using libraries that support polymorphic types without strict type checking. Prefer simple data formats like JSON without object graphs.\n\nUNSAFE:\n  boost::archive::text_iarchive ia(is);\n  ia >> myObject;\n\nSAFE:\n  // Parse JSON explicitly instead of automatic object graph deserialization"
    )

    write_rule(
        "cpp", "cpp_ssrf", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "Confirmed",
        "Server-Side Request Forgery via libcurl or Boost.Asio",
        "User input constructs a URL that the server requests. Attackers can scan internal networks.",
        CPP_SOURCES,
        ["curl_easy_setopt(curl, CURLOPT_URL,"],
        [],
        "Validate requested URLs against a strict allowlist. Do not allow users to specify arbitrary URLs to fetch.\n\nUNSAFE:\n  curl_easy_setopt(curl, CURLOPT_URL, user_url);\n\nSAFE:\n  // Validate user_url against an allowlist before passing to libcurl"
    )

    write_rule(
        "cpp", "cpp_integer_overflow", "Integer Overflow", "High", "CWE-190", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "Tentative",
        "Integer Overflow or Wraparound",
        "User-controlled integer values are used in arithmetic operations without bounds checking. Attackers can trigger overflows or underflows.",
        CPP_SOURCES,
        ["new ", "new[]", "std::vector", "std::malloc("],
        [],
        "Validate integer inputs before performing arithmetic operations. Consider using safe integer libraries or checking bounds against std::numeric_limits.\n\nUNSAFE:\n  size_t total = count * size;\n  char* buf = new char[total];\n\nSAFE:\n  if (count > MAX_COUNT) throw std::overflow_error(\"Count too large\");"
    )

    write_rule(
        "cpp", "cpp_out_of_bounds_read", "Memory Corruption", "High", "CWE-125", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Tentative",
        "Out-of-bounds Read via unchecked index",
        "User input controls the index used to access a buffer without bounds checking. Attackers can read sensitive data from adjacent memory locations.",
        CPP_SOURCES,
        ["[", "std::vector::operator[]", "std::array::operator[]"],
        ["std::vector::at(", "std::array::at("],
        "Always validate indices against the bounds of the array or vector. For STL containers, prefer the .at() method over the [] operator, as .at() performs bounds checking and throws std::out_of_range on failure.\n\nUNSAFE:\n  return myVector[userIndex];\n\nSAFE:\n  return myVector.at(userIndex);"
    )

if __name__ == '__main__':
    gen_c_cpp_rules()
