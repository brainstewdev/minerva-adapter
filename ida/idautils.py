import ghidra.app.script.GhidraScript # type: ignore
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI # type: ignore
from ghidra.program.flatapi import FlatProgramAPI # type: ignore


"""
    di questa classe devo mappare:
    call distance:
    - Functions(): restituisce tutte le funzioni (permette di ciclarci sopra!) (fatto, controllo formattazione voluta)
    - XrefsTo(parametri): restituisce le funzioni che fanno crossreference
        for xref in idautils.XrefsTo(func_ea, 0): fatto
"""

class idautils:
    # costruttore
    def __init__(self, state):
        self.__STATE = state # type: ignore
        self.__CUR_PROGRAM = self.__STATE.getCurrentProgram()
    def Functions(self):
        return self.__CUR_PROGRAM.getFunctionManager().getFunctions(True)
    # la flag non la implemento
    def XrefsTo(self, address, flag=0):
        fpi = FlatProgramAPI(self.__CUR_PROGRAM)
        fm = self.__CUR_PROGRAM.getFunctionManager()
        func = fm.getFunctionAt(address)
    
        print("\nFound func at entry point @ 0x{}".format(func.getEntryPoint()))
        entry_point = func.getEntryPoint()

        references = fpi.getReferencesTo(entry_point)
        print("debug: stampo xrefs:")
        for xref in references:
            print(xref)
        return references