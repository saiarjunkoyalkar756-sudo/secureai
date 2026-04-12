import ast
import json
import sys

class SecurityAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.results = {
            "imports": [],
            "calls": [],
            "attributes": [],
            "suspicious": []
        }
        self.dangerous_modules = {"os", "subprocess", "shutil", "socket", "requests", "urllib", "http", "sys", "pty"}
        self.dangerous_calls = {"eval", "exec", "getattr", "setattr", "delattr", "hasattr", "__import__", "compile", "open"}

    def visit_Import(self, node):
        for alias in node.names:
            self.results["imports"].append(alias.name)
            if alias.name in self.dangerous_modules:
                self.results["suspicious"].append(f"Import of dangerous module: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.results["imports"].append(node.module)
            if node.module in self.dangerous_modules:
                self.results["suspicious"].append(f"Import from dangerous module: {node.module}")
        self.generic_visit(node)

    def visit_Call(self, node):
        # Handle simple calls like eval(...)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            self.results["calls"].append(func_name)
            if func_name in self.dangerous_calls:
                self.results["suspicious"].append(f"Dangerous function call: {func_name}")
        
        # Handle attribute calls like os.system(...)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
                self.results["calls"].append(func_name)
                if node.func.attr in self.dangerous_calls or node.func.value.id in self.dangerous_modules:
                    self.results["suspicious"].append(f"Dangerous attribute call: {func_name}")

        self.generic_visit(node)

    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name):
            attr_path = f"{node.value.id}.{node.attr}"
            self.results["attributes"].append(attr_path)
        self.generic_visit(node)

def analyze_code(code):
    try:
        tree = ast.parse(code)
        analyzer = SecurityAnalyzer()
        analyzer.visit(tree)
        return {
            "status": "success",
            "analysis": analyzer.results
        }
    except SyntaxError as e:
        return {
            "status": "error",
            "message": f"Syntax Error: {str(e)}",
            "line": e.lineno
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Read from stdin if no file provided
        code_to_analyze = sys.stdin.read()
    else:
        with open(sys.argv[1], 'r') as f:
            code_to_analyze = f.read()

    result = analyze_code(code_to_analyze)
    print(json.dumps(result))
