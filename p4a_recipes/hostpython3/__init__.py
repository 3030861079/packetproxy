from pythonforandroid.recipe import PythonRecipe


class HostPython3Recipe(PythonRecipe):
    """
    Custom hostpython3 recipe that pins Python to 3.10.13.
    Python 3.13+ removed 'cgi' module which breaks Kivy's Cython build.
    """
    version = "3.10.13"
    url = "https://www.python.org/ftp/python/{version}/Python-{version}.tar.xz"
    name = "hostpython3"

    patches = []

    @property
    def should_build(self):
        return True

    def get_dir_name(self):
        return f"{self.name}-{self.version}"

    def pre_build_arch(self, arch):
        super().pre_build_arch(arch)

    def build_arch(self, arch):
        super().build_arch(arch)

    def get_recipe_env(self, arch=None, with_flags_in_cc=True):
        env = super().get_recipe_env(arch, with_flags_in_cc)
        return env


recipe = HostPython3Recipe()
