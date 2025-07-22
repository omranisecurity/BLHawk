import os
from modules.extractor import Extractor


def file_check(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            content = file.read().strip()
            Extractor(content)
    else:
        print('File', filename, 'does not exist.')