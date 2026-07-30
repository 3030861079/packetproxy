from pythonforandroid.recipes.hostpython3 import Hostpython3Recipe as Original


class Hostpython3Recipe(Original):
    version = "3.10.13"
    url = "https://www.python.org/ftp/python/{version}/Python-{version}.tar.xz"


recipe = Hostpython3Recipe()
