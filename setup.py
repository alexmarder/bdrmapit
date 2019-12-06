from Cython.Distutils import build_ext
from setuptools import setup, find_packages
from setuptools.extension import Extension
from Cython.Build import cythonize


extensions_names = {
    # 'bdrmapit_parser.parser.cyparser': ['bdrmapit_parser/parser/cyparser.pyx'],
    'bdrmapit_parser.graph.node': ['bdrmapit_parser/graph/node.pyx'],
    'bdrmapit_parser.graph.construct': ['bdrmapit_parser/graph/construct.pyx'],
    'bdrmapit_parser.algorithm.updates_dict': ['bdrmapit_parser/algorithm/updates_dict.pyx'],
    # 'bdrmapit_parser.algorithm.bdrmapit': ['bdrmapit_parser/algorithm/bdrmapit.pyx']
}

extensions = [Extension(k, v) for k, v in extensions_names.items()]
package_data = {k: ['*.pxd'] for k in extensions_names}

setup(
    name="bdrmapit_parser",
    version='0.1.1',
    packages=find_packages(),
    install_requires=['cython', 'jsonschema', 'deprecated', 'traceutils'],
    cmdclass={'build_ext': build_ext},
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            'language_level': '3',
            'embedsignature': True
        },
        annotate=True
    ),
    zip_safe=False,
    package_data=package_data,
    include_package_data=True
)
