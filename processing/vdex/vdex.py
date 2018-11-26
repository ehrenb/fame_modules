import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class VDEX(ProcessingModule):
    name = "vdex"
    description = "Perform static analysis on VDEX files"
    acts_on = "vdex"

    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")

    def each(self, target):
        self.results = dict()
        try:
            if not lief.VDEX.is_vdex(target):
                self.log('error', '{} is not a VDEX file'.format(target))
                return False
            vdex = lief.VDEX.parse(target)
            vdex_dict = json.loads(lief.to_json(vdex), parse_int=str)
            self.results.update(vdex_dict)

            # add extracted dex files
            for idx,dex_file in enumerate(vdex.dex_files):
                tempdir = tempdir()
                fname = 'classes_{}.dex'.format(str(idx))
                dex_filepath = os.path.join(tempdir, fname)
                dex_file.save(dex_filepath)
                if os.path.isfile(dex_filepath):
                    self.add_extracted_file(dex_filepath)

        except:
            self.log('error', traceback.print_exc())
        return True