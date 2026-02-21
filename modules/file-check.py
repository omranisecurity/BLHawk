import os
from modules.extractor import Extractor


def file_check(filename: str) -> None:
    """Read `filename` and pass its content to the extractor."""
    if not os.path.isfile(filename):
        print(f'File {filename} does not exist.')
        return

    with open(filename, 'r') as fh:
        content = fh.read().strip()
    if content:
        Extractor(content)