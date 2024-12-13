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