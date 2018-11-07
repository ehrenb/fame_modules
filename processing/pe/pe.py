import traceback

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

class PE(ProcessingModule):
    name = "pe"
    description = "Perform static analysis on PE files"
    acts_on = ["exe", "executable", "dll"]

    def initialize(self):
        if not HAVE_PEFILE:
            raise ModuleInitializationError(self, "Missing dependency: pefile")

    def each(self, target):
        self.results = dict()
        try:
            pe = pefile.PE(target)
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            base = pe.OPTIONAL_HEADER.ImageBase
            sections = pe.FILE_HEADER.NumberOfSections
            imported_symbols = []
            exported_symbols = []

            try:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    imported = {'dll': entry.dll,
                                'functions': []}
                    for imp in entry.imports:
                        imported['functions'].append({'address': hex(imp.address),
                                                      'name': imp.name})
                    imported_symbols.append(imported)
            except AttributeError:
                print('[+] {}'.format(traceback.print_exc()))

            try:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exported = {'address': hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), 
                                'name': exp.name,
                                'ordinal': exp.ordinal}
                    exported_symbols.append(exported)
            except AttributeError:
                print('[+] {}'.format(traceback.print_exc()))

            self.results['entrypoint'] = ep
            self.results['base'] = base
            self.results['num_sections'] = sections
            self.results['imported_symbols'] = imported_symbols
            self.results['exported_symbols'] = exported_symbols

        except:
            print('[+] {}'.format(traceback.print_exc()))
        return True 