from pycparser import parse_file, c_ast, c_generator
import argparse
import subprocess
import os

class FunctionCallExtractor(c_ast.NodeVisitor):
    def __init__(self, ast):
        self.ast = ast
        self.calls = []
        self.visited_functions = set()
        self.function_prototypes = {}
        self.generator = c_generator.CGenerator()

    def visit_FuncCall(self, node):
        func_name = self._get_func_name(node)
        if func_name not in self.visited_functions:
            func_args = self._get_func_args(node)
            self.calls.append((func_name, func_args))
            self.generic_visit(node)
            self.function_by_name(func_name)

    def _get_func_name(self, node):
        if isinstance(node.name, c_ast.ID):
            return node.name.name
        elif isinstance(node.name, c_ast.StructRef):
            return self._get_func_name(node.name)
        return "[Unknown Function]"

    def _get_func_args(self, node):
        func_args = []
        if node.args:
            for expr in node.args.exprs:
                func_args.append(self.generator.visit(expr))
        return func_args

    def function_by_name(self, func_name):
        for ext in self.ast.ext:
            if isinstance(ext, c_ast.FuncDef) and ext.decl.name == func_name:
                self.visited_functions.add(func_name)
                self.visit(ext)
                break


def process_c_file(c_file_path, entry_func="main"):
    # ast = parse_file(c_file_path, use_cpp=True, cpp_path="/home/kruta/qnx/qnx800/host/linux/x86_64/usr/bin/qcc",
    #                  cpp_args=["-P","-I/home/kruta/qnx/qnx800/target/qnx/usr/include"])
    # ast = parse_file(c_file_path, use_cpp=True, cpp_path="gcc", cpp_args=['-E',"-I/home/kruta/pycparser/utils"
    #                                                                            "/fake_libc_include"])

    ast = parse_file(c_file_path, use_cpp=False)
    extractor = FunctionCallExtractor(ast)
    extractor.function_by_name(entry_func)  # Start with entry function
    return extractor.calls


def get_the_preprocessed_file(file_path=None, qcc_path=None, include_path=None):
    command = ['./preprocessed_file.sh', file_path, qcc_path, include_path]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == -1:
        print("Error:", result.stderr)
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="python3 SecGenTool.py /home/source_file.c "
                                                 "/home/qnx/host/linux/x86_64/usr/bin/qcc  main"
                                                 "/home/qnx/target/qnx/usr/include /home/project/include")
    parser.add_argument("source_file_path", help="The path of the .c file.")
    parser.add_argument("qcc_path", help="path of qcc usually e.g.qnx/host/linux/x86_64/usr/bin/qcc")
    parser.add_argument("entry_funct", help="provide the entry point of this file e.g. main")
    parser.add_argument("include_path", nargs="*", help="list of different include path required to build this file. "
                                                        "e.g. -/home/qnx/target/qnx/usr/include "
                                                        "-/home/project/include")
    # Parse arguments
    args = parser.parse_args()
    inc_path = args.include_path
    inc_path[0] = "-I" + inc_path[0]
    inc_path = ' -I'.join(inc_path)

    get_the_preprocessed_file(args.source_file_path, args.qcc_path, inc_path)
    calls = process_c_file("output_file.c", "main")
    # print(calls)
    for func, args in calls:
        print(func, ":", args)
    if os.path.exists("output_file.c"):
        os.remove("output_file.c")
