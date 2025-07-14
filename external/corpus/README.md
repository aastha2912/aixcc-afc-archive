This generates some pre-populated fuzzing data that may be useful for harnesses of standard file types.

To use:
 1. pip install tqdm
 2. run corpus.py
 3. go grab a coffee while it runs for a while
 4. upload to azure `azcopy copy sample.tar.xz https://de6543ab956de244.blob.core.windows.net/files/` and `azcopy copy corpus https://de6543ab956de244.blob.core.windows.net/files/ --recursive`
