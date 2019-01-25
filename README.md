# bdrmapit_parser
This file explains how to run the new version of bdrmapIT.
bdrmapIT relies on the [traceutils](https://github.com/alexmarder/traceutils) package, which contains a lot of utilies.

## Compilation
The recommended way to run bdrmapIT is to first set up an [Anaconda](https://www.anaconda.com/) environment.
Once Anaconda is installed, create an environment,
```bash
conda create -n <env> python=3
conda activate <env>
conda install cython
```
where \<env\> is the name of the environment.

First, compile and install the [traceutils](https://github.com/alexmarder/traceutils) package.
Make sure to clone traceutils and bdrmapit_parser into a different directories.
```bash
git clone https://github.com/alexmarder/traceutils
cd traceutils
python setup.py sdist bdist_wheel && pip install .
```

Then, compile the bdrmapit_parser package.
```bash
git clone https://github.com/alexmarder/bdrmapit_parser
cd bdrmapit_parser
python setup.py build_ext --inplace
```

## Prepare Inputs
bdrmapIT pulls in a bunch of information to inform its inferences.
To use the publicly available CAIDA archived data, refer to the [retrieve-external](https://github.com/alexmarder/retrieve-external).

### Prefix to AS Mappings
The CAIDA prefix2as mappings are insufficient.
To properly prepare a list of mappings, refer to the [ip2as](https://github.com/alexmarder/ip2as) package.

### AS
An AS-to-Organization dataset in CAIDA format is required.
If desired, an additional file with siblings can be provided. 