= Certificate Lints

== Description
This directory contains linting modules used by the ```lint.sh``` wrapper to validate X.509 certificates.
This directory is populated in part through Git submodules configured in the ```../.gitmodules``` file, while others represent static tests.

== Building
You can build all of the submodules in this folder by running ```make```:
```bash
make all
```

To list individual ```make``` targets, run:
```bash
make list
```

To run ```make``` with some additional debugging information, run:
```bash
make --debug=v all
```
