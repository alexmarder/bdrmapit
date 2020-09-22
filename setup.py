import sys
from setuptools import setup, find_packages
from setuptools.extension import Extension

if 'build_ext' in sys.argv:
    from Cython.Distutils import build_ext
    use_cython = True
else:
    use_cython = False

ext_pyx = '.pyx' if use_cython else '.c'
extensions_names = {
    'bdrmapit.graph.node': ['bdrmapit/graph/node' + ext_pyx],
    'bdrmapit.graph.construct': ['bdrmapit/graph/construct' + ext_pyx],
    'bdrmapit.algorithm.updates_dict': ['bdrmapit/algorithm/updates_dict' + ext_pyx],
}

extensions = [Extension(k, v) for k, v in extensions_names.items()]
package_data = {k: ['*.pxd', '*pyx', '*.py'] for k in extensions_names}

if use_cython:
    from Cython.Build import cythonize
    extensions = cythonize(
        extensions,
        compiler_directives={'language_level': '3', 'embedsignature': True},
        annotate=True
    )

setup(
    name="bdrmapit",
    version='0.1.1',
    packages=find_packages(),
    install_requires=['jsonschema', 'traceutils>=6.15.7'],
    python_requires='>=3, !=3.8',
    ext_modules=extensions,
    entry_points={
        'console_scripts': [
            'bdrmapit=scripts.bdrmapit:main',
            'traceparser=scripts.traceparser:main'
        ],
    },
    zip_safe=False,
    package_data=package_data,
    include_package_data=True
)
