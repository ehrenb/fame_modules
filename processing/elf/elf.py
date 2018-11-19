import json
import traceback

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class ELF(ProcessingModule):
    name = "elf"
    description = "Perform static analysis on ELF files"
    acts_on = "elf"

    def initialize(self):
        pass

    def each(self, target):
        self.results = dict()
        return True