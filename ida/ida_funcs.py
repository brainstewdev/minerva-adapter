import ghidra.app.script.GhidraScript # type: ignore
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI # type: ignore
from ghidra.program.flatapi import FlatProgramAPI # type: ignore

"""
funzioni richieste (da call distance):
    - ida_funcs.get_func(xref.frm) 
        frm sarebbe da dove inizia la funzione
"""

class ida_funcs:
    def __init__(self, state):
        self.__STATE = state
        self.__CUR_PROGRAM = state.getCurrentProgram()
    """
        funzione che restituisce l'oggetto funzione che inizia dall ind che viene passato
    """
    def get_func(self, addr_from):
        return self.__CUR_PROGRAM.getFunctionManager().getFunctionAt(addr_from)