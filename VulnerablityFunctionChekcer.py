import clang.cindex

# 취약 함수와 버전 정보
VULNERABLE_FUNCTIONS = {
    "strcpy": "C++ Standard Library",
    "strcat": "C++ Standard Library",
    "sprintf": "C++ Standard Library",
    "printf": "C++ Standard Library",
    "gets": "C++ Standard Library",
    "strcmp": "C++ Standard Library",
}

class CppVulnerabilityDetector:
    def __init__(self, filename):
        self.filename = filename
        self.index = clang.cindex.Index.create()

    def parse(self):
        # C++ 파일을 파싱하여 AST를 생성
        if(self.filename == None):
          assert True, "filename is null"
        translation_unit = self.index.parse(self.filename)
        return translation_unit

    def print_ast(self, node, depth=0):
        # AST 노드를 출력하는 재귀 함수
        print("  " * depth + f"{node.kind} : {node.spelling}")
        for child in node.get_children():
            self.print_ast(child, depth + 1)

    def detect_vulnerabilities(self, node):
        # 노드가 함수 호출일 경우, 취약 함수를 탐지
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            if node.spelling in VULNERABLE_FUNCTIONS:
                print(f"Vulnerable function '{node.spelling}' called at {node.location}")
                print(f"Version Info: {VULNERABLE_FUNCTIONS[node.spelling]}")
        
        # 자식 노드를 재귀적으로 탐색
        for child in node.get_children():
            self.detect_vulnerabilities(child)

if __name__ == "__main__":
    cpp_file = 'target.cpp'  # 파싱할 C++ 파일 경로

    # CppVulnerabilityDetector 클래스의 인스턴스 생성 및 파싱 실행
    detector = CppVulnerabilityDetector(cpp_file)
    translation_unit = detector.parse()

    # 취약 함수 탐지
    detector.detect_vulnerabilities(translation_unit.cursor)
