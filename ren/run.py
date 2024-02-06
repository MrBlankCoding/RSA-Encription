import sys

from .myapp.main import create_app

sys.path.append("..")

app = create_app()
