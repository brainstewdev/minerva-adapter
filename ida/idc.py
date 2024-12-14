"""
    funzioni da adattare:
    - get_idb_path: restituisce la path dell'oggetto idb (sarebbe in caso di ghidra la path del programma).
        dalla doc: This function returns full path of the current IDB database
"""
class idc:
    def __init__(self, state):
        self.__STATE = state
        pass
    # faccio restituire la path direttamente alla root del progetto, nel caso poi fixo
    def get_idb_path(self):
        project = self.__STATE.getProject()
        locator = project.getProjectData().getProjectLocator()
        print(locator.getLocation())
    """
    get a function attribute
        ea   - any address belonging to the function
        attr - one of FUNCATTR_... constants
    """
    def get_func_attr(self, ea, attr):
        address_size = self.__STATE.getCurrentProgram().getAddressFactory().getDefaultAddressSpace().getSize()
        # Definizione costanti in Python
        EA64 = (address_size == 64)
        
        if not EA64:  # Configurazione per 32-bit
            FUNCATTR_START = 0     # readonly: function start address
            FUNCATTR_END = 4       # readonly: function end address
            FUNCATTR_FLAGS = 8     # function flags
            FUNCATTR_FRAME = 16    # readonly: function frame id
            FUNCATTR_FRSIZE = 20   # readonly: size of local variables
            FUNCATTR_FRREGS = 24   # readonly: size of saved registers area
            FUNCATTR_ARGSIZE = 28  # readonly: number of bytes purged from the stack
            FUNCATTR_FPD = 32      # frame pointer delta
            FUNCATTR_COLOR = 36    # function color code
            FUNCATTR_OWNER = 16    # readonly: chunk owner (valid only for tail chunks)
            FUNCATTR_REFQTY = 20   # readonly: number of chunk parents (valid only for tail chunks)
        else:  # Configurazione per 64-bit
            FUNCATTR_START = 0
            FUNCATTR_END = 8
            FUNCATTR_FLAGS = 16
            FUNCATTR_FRAME = 24
            FUNCATTR_FRSIZE = 32
            FUNCATTR_FRREGS = 40
            FUNCATTR_ARGSIZE = 48
            FUNCATTR_FPD = 56
            FUNCATTR_COLOR = 64
            FUNCATTR_OWNER = 24
            FUNCATTR_REFQTY = 32
        # per ora devo implementare funztion start
        if(attr == FUNCATTR_START):
            return self.__STATE.getCurrentProgram().getFunctionManager().getFunctionContaining(ea)