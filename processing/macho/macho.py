import json
import traceback

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class MachO(ProcessingModule):
    name = "macho"
    description = "Perform static analysis on MachO files"
    acts_on = "macho"

    def initialize(self):
        pass

    def each(self, target):
        self.results = dict()
        return True