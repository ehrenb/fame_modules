import json
import traceback

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class OAT(ProcessingModule):
    name = "oat"
    description = "Perform static analysis on OAT files"
    acts_on = "oat"

    def initialize(self):
        pass

    def each(self, target):
        self.results = dict()
        return True