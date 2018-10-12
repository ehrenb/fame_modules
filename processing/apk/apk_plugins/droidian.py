import json
import base64
from . import APKPlugin


class Droidian(APKPlugin):
    name = "droidian"
    extraction = "Droidian Configuration"
    probable_name = "Droidian"

    def run(self, module):
        cls = self.get_droidian_service()

        if cls is None:
            return None

        hosts = set()
        string = None
        for method in cls.get_methods():
            if method.name == '<init>':
                for inst in method.get_instructions():
                    if inst.get_name() == 'const-string':
                        string = inst.get_output().split(',')[-1].strip(" '")
                        try:
                            string = base64.b64decode(string)
                        except:
                            string = None
                    elif string and inst.get_name() == 'iput-object' and inst.get_output().split('->')[-1].startswith('encodedURL') or inst.get_output().split('->')[-1].startswith('backupURL'):
                        hosts.add(string)

        module.add_ioc(hosts, ['droidian', 'c2'])

        return json.dumps({'c2': list(hosts)}, indent=2)

    def get_droidian_service(self):
        classes = []
        for v in self.vm:
            classes.extend(v.get_classes())
        for cls in classes:
            for field in cls.get_fields():
                if field.name in ['backupURL', 'encodedURL']:
                    return cls

        return None
