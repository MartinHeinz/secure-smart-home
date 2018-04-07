#!C:\Users\MH\Desktop\diplomovka\secure-smart-home\secure_smart_home\Scripts\python.exe
# EASY-INSTALL-ENTRY-SCRIPT: 'python-lambda-local==0.1.5','console_scripts','python-lambda-local'
__requires__ = 'python-lambda-local==0.1.5'
import re
import sys
from pkg_resources import load_entry_point

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(
        load_entry_point('python-lambda-local==0.1.5', 'console_scripts', 'python-lambda-local')()
    )
