# Compilation
There are several packages involved in running bdrmapIT. Some are required and some are optional for added convenience. To avoid potential problems, make sure to clone each package into separate directories.

## Required Packages
There are three required packages:
1. <tt>traceutils</tt> – set of utilities that enable the other required packages
2. <tt>ip2as</tt> – creates the prefix to AS mappings needed to determine the origin AS for each IP address
3. <tt>bdrmapit_parser</tt> – runs <tt>bdrmapIT</tt>

## Optional Packages
There is one optional package that makes retrieving datasets easier.
1. <tt>retrieve_external</tt> – package for retrieving publicly available CAIDA datasets, RIR delegations, and BGP route announcements

# Python Environment
It’s easiest to create a new python environment for <tt>bdrmapIT</tt>. Anything capable of creating and isolating a python environment will work, but all examples assume [Anaconda](https://www.anaconda.com/).
First, install Anaconda according to the instructions there. Then, create the environment to install the <tt>bdrmapIT</tt> packages. Here, the environment name <tt>bdrmapit</tt> is used, but any name works.

```bash
# create environment with latest version of python3
conda create -n bdrmapit python=3
# activate the new environment
conda activate bdrmapit
```

# Installing Traceutils
The first step is to install <tt>traceutils</tt>, a prerequisite for creating prefix-to-AS mappings and running <tt>bdrmapIT</tt>. I don’t think the installation will work on Windows, but should work on macos and Linux distributions. To install, follow the directions in the [<tt>traceutils</tt> readme](https://github.com/alexmarder/traceutils).

# Retrieving Datasets
A lot of datasets go into <tt>bdrmapIT</tt>’s inferences. All of it can be retrieved using the retrieve_external package, but it is not necessary to use it for some or all of the datasets. The examples here assume that the <tt>retrieve_external</tt> package is use. Information is provided in the [<tt>retrieve_external</tt> repo](https://github.com/alexmarder/retrieve-external/wiki).

# Create Prefix to AS
It is not necessary to use the <tt>ip2as</tt> repository to create the prefix to AS mappings if you have your own mappings. Otherwise, run the scripts as described [there](https://github.com/alexmarder/ip2as/wiki)

# Running bdrmapIT
Finally, using the prefix to AS mappings, we can run <tt>bdrmapIT</tt>. First, clone the new <tt>bdrmapIT</tt> repository,
and compile the cython code.
```bash
git clone https://github.com/alexmarder/bdrmapit_parser
cd bdrmapit_parser
python setup.py build_ext --inplace
```

Then, use the main script, <tt>bdrmapit.py</tt> to parse the traceroutes, run the <tt>bdrmapIT</tt> algorithm, and output the annotations for routers and interfaces. Due to the many input file, we use a JSON configuration file to provide the runtime parameters. The JSON file uses the schema described in schema.json, which uses the JSON Schema format.
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

After generating the configuration file, run <tt>bdrmapit.py</tt>, with arguments,

Argument | Required | Description
--- | --- | ---
-o, --output | Required | Output filename for sqlite3 output.
-c, --config | Required | JSON configuration file in accordance with schema.json

The output is an sqlite3 file with a single table named annotation. The table has the following fields,

Field | Type | Description
--- | --- | ---
addr | TEXT | Interface address
asn | INT | Operating AS for the router on which addr resides (router annotation)
org | TEXT | AS2Org mapping for asn
conn_asn | INT | Operating AS for router connected to addr (interface annotation)
conn_org | TEXT | AS2Org mapping for conn_asn

Warning: oversimplification coming, but a brief explanation of what the annotations represent. Every interface is used on a router. <tt>asn</tt> indicates the network that operates that router. Every interface is also used to connect to at least one other router. <tt>conn_asn</tt> indicates the network that operates that router or routers. To look for inferred interdomain links, look for <tt>addr</tt> where <tt>asn</tt> &ne; <tt>conn_asn</tt>.