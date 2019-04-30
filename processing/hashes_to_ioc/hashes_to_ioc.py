import hashlib

from fame.core.module import ProcessingModule

hash_algorithms = ['sha1', 'sha256', 'sha512', 'md5']

def get_hash(f_path, mode):
    h = hashlib.new(mode)
    with open(f_path, 'rb') as file:
        data = file.read()
    h.update(data)
    digest = h.hexdigest()
    return digest

class HahesToIOC(ProcessingModule):
    name = "hashes_to_ioc"
    description = "Creates IOCs out of various hashes of the sample, sending them to Threat Intelligence modules if enabled"

    def each(self, target):
        for mode in hash_algorithms:
            h = get_hash(target, mode)
            self.add_ioc(h)
