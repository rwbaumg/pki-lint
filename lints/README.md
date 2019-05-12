# Certificate Lints

## Description
This directory contains linting modules used by the ```lint.sh``` wrapper to validate X.509 certificates.
This directory is populated in part through Git submodules configured in the ```../.gitmodules``` file, while others represent static tests.

## Building
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

---

## zlint
The ```lint.sh``` script uses a few tricks to parse the json-formatted output from the ```zlint``` linting module.

After building the ```zlint``` module a symlink is created under ```./bin/zlint``` for easy reference.

A few example ```zlint``` commands are shown below:

  - To list the names of every lint:
    ```bash
    ./bin/zlint -list-lints-json \
      | while read x; do echo $x \
      | grep -Po '(?<=name\"\:\")[^\"]+(?=\"\,\")'; done
    ```

  - To list the description text for every lint:
    ```bash
    ./bin/zlint -list-lints-json \
      | while read x; do echo $x \
      | grep -Po '(?<=description\"\:\")[^\"]+(?=\"\,\")'; done
    ```

---

Unpublished Copyright 2019 © Robert W. Baumgartner. All rights reserved.
