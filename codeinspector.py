import abc
import clang.cindex
from collections import deque

class code_inspector:

    __metaclass__=abc.ABCMeta

    code_parser = clang.cindex.Index.create()
    code_context:clang.cindex = None

    def __init__(self,node = None):
        code_inspector.code_context = node
        if code_inspector.code_context is None :
            assert False, "you must insert code node at inialize this class"
        

    abc.abstractmethod
    def inspect(self,node) -> list:
        pass

    abc.abstractmethod
    def add_inspect_List(self,inspectList:list):
        pass

    def change_code_context(self,node):
        code_inspector.code_context = node


class harmful_function_inspector(code_inspector):
    
    def __init__(self,node=None):
        super().__init__(node)
        self.harmful_api_list = deque()

    def inspect(self) -> list:
        pass

    def add_inspect_List(self, inspect_list: list):
        self.add_inspect_List.append(inspect_list)
    

class cve_code_inspector(code_inspector):

    cve_dict = dict()
    
    def __init__(self, node=None):
        super().__init__(node)

    def inspect(self, node) -> list:
        return super().inspect(node)
    
    def add_inspect_List(self, inspectList: dict):
        pass

    