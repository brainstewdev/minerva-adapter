#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
    # flag implementate per 1
    def XrefsTo(self, address, flag=0):
        if flag == 0:
            fpi = FlatProgramAPI(self.__CUR_PROGRAM)
            fm = self.__CUR_PROGRAM.getFunctionManager()
            func = fm.getFunctionAt(address)
        
            entry_point = func.getEntryPoint()

            references = fpi.getReferencesTo(entry_point)
            return references
        elif flag == 1:
            ref_manager = self.__CUR_PROGRAM.getReferenceManager()
            memory = self.__CUR_PROGRAM.getMemory()
            func_manager = self.__CUR_PROGRAM.getFunctionManager()

            # ottengo indirizzo target (non so come mi è stato passato l'indirizzo, meglio andare sul sicuro (un po' overkill))
            target_address = self.__CUR_PROGRAM.getAddressFactory().getAddress(address.getAddressSpace().getSpaceID(), address.getOffset())
            if not target_address:
                raise ValueError("Indirizzo {} non valido.".format(address))

            # ottengo riferimenti per l'indirizzo
            refs = ref_manager.getReferencesTo(target_address)
            far_refs = []
            for ref in refs:
                from_address = ref.getFromAddress()

                # Controlla se il riferimento è "far"
                # arriva da un segmento diverso?
                from_block = memory.getBlock(from_address)
                to_block = memory.getBlock(target_address)
                if from_block != to_block:
                    far_refs.append(ref)
                    continue

                # arriva da una funzione diversa?
                from_func = func_manager.getFunctionContaining(from_address)
                to_func = func_manager.getFunctionContaining(target_address)
                if from_func != to_func:
                    print(ref)
                    far_refs.append(ref)
            return far_refs
