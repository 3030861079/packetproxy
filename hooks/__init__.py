"""
python-for-android 构建钩子
在Android上运行时自动请求前台服务权限
"""

from pythonforandroid.toolchain import PythonRecipe, current_directory


def on_droid_import(import_name):
    """在Android上导入android模块时调用"""
    pass
