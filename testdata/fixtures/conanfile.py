from conan import ConanFile

class MyProject(ConanFile):
    name = "myproject"
    version = "1.0"

    python_requires = "cmake-conan/0.17.0@conan/stable"

    requires = ["fmt/10.1.1", "spdlog/1.12.0"]

    def requirements(self):
        self.requires("openssl/3.1.4@conan/stable#deadbeef1234")
        self.requires("zlib/1.2.13")
        self.build_requires("cmake/3.27.0")
