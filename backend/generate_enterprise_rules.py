import os
from pathlib import Path
from generate_rules_python import gen_python_rules
from generate_rules_js import gen_js_rules
from generate_rules_java import gen_java_rules
from generate_rules_php import gen_php_rules
from generate_rules_go_csharp import gen_go_csharp_rules
from generate_rules_c_cpp import gen_c_cpp_rules

def main():
    print("Generating strict, consolidated enterprise rulesets...")
    
    gen_python_rules()
    print("Python rules generated.")
    
    gen_js_rules()
    print("JavaScript rules generated.")
    
    gen_java_rules()
    print("Java rules generated.")
    
    gen_php_rules()
    print("PHP rules generated.")
    
    gen_go_csharp_rules()
    print("Go and C# rules generated.")
    
    gen_c_cpp_rules()
    print("C and C++ rules generated.")
    
    print("Generation complete. Run validate_rules.py to verify.")

if __name__ == '__main__':
    main()
