"""resolve abstract types for files using Lief"""

import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class LiefDetector(ProcessingModule):
    name = 'liefdetector'
    description = 'Use lief to detect & change abstract types of binaries for new analyses'
    triggered_by = "!type_resolved"
    
    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")

    def each(self, target):
        # Prevent circular detection


        self.results = dict()
        if self.type_resolved(target):
            self.add_tag('type_resolved')
            return True
        else:
            self.log('warn', 'Lief could not resolve abstract type')
        return False

    def type_resolved(self, target):
        new = None
        if lief.is_pe(target):
            new = 'executable'
        elif lief.is_elf(target):
            new = 'elf'
        elif lief.is_oat(target):
            new = 'oat'
        elif lief.is_dex(target):
            new = 'dex'
        elif lief.is_vdex(target):
            new = 'vdex'
        elif lief.is_art(target):
            new = 'art'
        if new:
            self.change_type(target, new)
            self.results['message'] = 'File type was changed to {}.'.format(new)
            return True
        return False
            


 