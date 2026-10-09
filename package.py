name = "python"
version = "3.7.9"
description = "CPython 3.7.9 standalone interpreter with standard library and development files"

tools = ["python"]
variants = [
    ["platform-windows", "arch-x86_64"],
    ["platform-linux", "arch-x86_64"],
    ["platform-osx", "arch-x86_64"],
]


def commands():
    env.PATH.prepend("{root}/payload/install")
    env.PATH.prepend("{root}/payload/install/bin")
