---
title: bdrmapIT Documentation
---

# Prerequisites
## Python Environment
It’s easiest to create a new python environment for <tt>bdrmapIT</tt>. Anything capable of creating and isolating a python environment will work, but all examples assume [Anaconda](https://www.anaconda.com/).
First, install Anaconda according to the instructions there. Then, create the environment to install the <tt>bdrmapIT</tt> packages. Here, the environment name <tt>bdrmapit</tt> is used, but any name works.

```bash
# create environment with python3.7
conda create -n bdrmapit python=3.7
# activate the new environment
conda activate bdrmapit
```

**cython currently prevents using python >= 3.8**

## Required Packages
There are three required packages:
1. [<tt>traceutils</tt>](https://github.com/alexmarder/traceutils) – set of utilities that enable the other required packages (`pip install -U traceutils`)
2. [<tt>ip2as</tt>](https://github.com/alexmarder/ip2as/wiki) – creates the prefix to AS mappings needed to determine the origin AS for each IP address (`pip install -U ip2as`)
3. <tt>bdrmapit</tt> – runs <tt>bdrmapIT</tt>

## Optional Packages
There is one optional package that makes retrieving datasets easier.
1. <tt>retrieve_external</tt> – package for retrieving publicly available CAIDA datasets, RIR delegations, and BGP route announcements

# Installing bdrmapIT
## Install Using pip
It is now possible to install bdrmapIT and the required repositories using pip and python3.
Make sure to first install `traceutils` and `ip2as` (e.g. `pip install -U traceutils ip2as`).
Then install the bdrmapit package `pip install -U bdrmapit`.

## Compilation From Source
There are several packages involved in running bdrmapIT.
Some are required, and some are optional for added convenience.
The source code repository resides at [https://github.com/alexmarder/bdrmapit](https://github.com/alexmarder/bdrmapit).

Clone the <tt>bdrmapIT</tt> repository, and compile the cython code.
```bash
git clone https://github.com/alexmarder/bdrmapit
cd bdrmapit
# install required packages
pip install -r requirements.txt
# compile cython code and build package
python setup.py sdist bdist_wheel build_ext
# install using developer mode, will install the bdrmapit and traceparser scripts
pip install -e .
```

## Scripts
Regardless of the installation method, a script will be installed into the python environment.
This script, `bdrmapit` can be called from the command line when inside the python environment.

# Running bdrmapIT
## Create Prefix to AS
Run the scripts as described [here](https://github.com/alexmarder/ip2as/wiki).

## Retrieving Datasets
A lot of datasets go into <tt>bdrmapIT</tt>’s inferences.
All of it can be retrieved using the retrieve_external package, but it is not necessary to use it for some or all of the datasets.
The examples here assume that the <tt>retrieve_external</tt> package is use.
Information is provided in the [<tt>retrieve_external</tt> repo](https://github.com/alexmarder/retrieve-external/wiki).

## Configuration File
Finally, using the prefix to AS mappings, we can run <tt>bdrmapIT</tt>.
Then, use the main script, <tt>bdrmapit.py</tt> to parse the traceroutes, run the <tt>bdrmapIT</tt> algorithm, and output the annotations for routers and interfaces.
Due to the many input file, we use a JSON configuration file to provide the runtime parameters.
The JSON file uses the schema described in [schema.json](https://github.com/alexmarder/bdrmapit/blob/master/schema.json), which uses the JSON Schema format.
As a sample, the following could be in a configuration file:
```json
{
    "$schema": "schema.json",
    "ip2as": "ip2as.prefixes",
    "as2org": {
        "as2org": "as2org-file"
    },
    "as-rels": {
        "rels": "rels-file",
        "cone": "cone-file"
    },
    "warts": {
        "files": "warts.files"
    },
    "atlas": {
        "files-list": ["atlas_file.json.bz2"]
    },
    "processes": 3
}
```
<tt>warts.files</tt> is a file containing warts filenames (line separated), and <tt>atlas_file.json.bz2</tt> is a RIPE Atlas traceroute file. Of course, individual files and a file with filenames could be supplied for warts, atlas, or both.
*Only use <tt>atlas-odd</tt> if you know why you're using it.*

## Run bdrmapit Script
After generating the configuration file, run <tt>bdrmapit</tt>, with arguments,

Argument | Required | Description
:--- | :--- | :---
-o, --output | Required | Output filename for sqlite3 output.
-c, --config | Required | JSON configuration file in accordance with schema.json
-n, --nodes-as | Optional | Filename for output in the CAIDA nodes.as style
-g, --graph | Optional | Graph pickle object created by --graph-only
--graph-only | Optional | Create graph pickle object, save pickle in file specified by -o/--output, and exit

Example: `bdrmapit -o annotations.db -c config.json`

## Output
The output is an sqlite3 file with a table named annotation.
The table has the following fields,

Field | Type | Description
:--- | :--- | :---
addr | TEXT | Interface address
asn | INT | Operating AS for the router on which addr resides (router annotation)
org | TEXT | AS2Org mapping for asn
conn_asn | INT | Operating AS for router connected to addr (interface annotation)
conn_org | TEXT | AS2Org mapping for conn_asn

Warning: oversimplification coming, but a brief explanation of what the annotations represent.
Every interface is used on a router.
<tt>asn</tt> indicates the network that operates that router.
Every interface is also used to connect to at least one other router.
<tt>conn_asn</tt> indicates the network that operates that router or routers.
To look for inferred interdomain links, look for <tt>addr</tt> where <tt>asn</tt> &ne; <tt>conn_asn</tt>.

### Unusual Output
A small number of routers might receive annotations with invalid AS numbers in the <tt>asn</tt> column:

ASN | Explanation
:--- | :---
0 | Address has no covering prefix in the prefix-to-AS mappings, and insufficient information in the graph to derive an ASN
-1 | Should be rare; occurs when bdrmapIT failed to assign the router an annotation
<= -100 | IXP public peering address with insufficient graph information for an AS annotation

All outputs will likely contain some amount of these invalid ASNs, but it should be relatively rare.