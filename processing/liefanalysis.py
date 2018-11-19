"""resolve abstract types for files using Lief, also if resolved, do some basic static analysis"""

import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class LiefAnalysis(ProcessingModule):
    name = 'liefanalysis'
    description = 'Perform static analysis on elf, dex, executable, macho, oat, vdex, and art and change abstract type for new analysis'
    acts_on = '*'

    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")

    def each(self, target):
        self.results = dict()

        if self.type_resolved(target):
            try:
                binary = lief.parse(target)
                binary_dict = json.loads(lief.to_json(binary))
                self.results.update(binary)

            except:
                self.log('error', traceback.print_exc())
        else:
            self.log('warn', 'Lief could not resolve abstract type')

        return True

    def type_resolved(self, target):
        if lief.is_pe(target):
            self.change_type(target, 'executable')
        elif lief.is_elf(target):
            self.change_type(target, 'elf')
        elif lief.is_oat(target):
            self.change_type(target, 'oat')
        elif lief.is_dex(target):
            self.change_type(target, 'dex')
        elif lief.is_vdex(target):
            self.change_type(target, 'vdex')
        elif lief.is_art(target):
            self.change_type(target, 'art')
        else:
            return False
        return True


