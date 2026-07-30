from pythonforandroid.recipes.hostpython3 import Hostpython3Recipe as Base


class HostPython3Recipe(Base):
    """Override default hostpython3 to pin Python 3.10.13.

    Python 3.13+ removed 'cgi' which breaks Cython 0.29.x used by Kivy <=2.2.1.
    """
    version = "3.10.13"
    url = "https://www.python.org/ftp/python/{version}/Python-{version}.tar.xz"
    name = "hostpython3"

    def get_dir_name(self):
        return "hostpython3-{}".format(self.version)

    @property
    def should_build(self):
        return True


recipe = HostPython3Recipe()
