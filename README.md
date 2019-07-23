# Python library for Generic Netlink

At [Blu Wireless](https://bluwireless.com/) we needed a tool for doing NL80211
interactions in Python test code. We couldn't find any libraries that
facilitate this in a way that leverages the strengths of Python, so we wrotedirectory
something. Most of the original code was specific to Blu Wireless' technology,
but the generic stuff was pulled out to create this library.

Netlink and Generic Netlink themselves aren't very complicated, but the
attribute system can result in reams of boilerplate code. The aim of this
library is to reduce that boilerplate. The key observation is that for
some/most/all genl families, given knowledge about which attributes appear in
which context and what type their payload should have, attribute sets can be
mapped to Python dictionaries. So to use this library you provide a _schema_
expressing that knowledge about attribute semantics in the protocol you're
using, and it gives you an ergonomic way to build and parse messages.

The best way to see what this really means is to take a look at nl80211.py,
where we define an example schema for NL80211 commands, and
examples/nl80211_dump.py, which uses that schema to query NL80211 for
information about a given WiFi adapter.

Works on both Python 2 and 3. Pure Python, no dependencies.

## Known limitations

- It would make sense for this library to help you build and parse multi-part
  Netlink messages, but it doesn't.

- No HTML documentation. There are docstrings in the code, though. The most
  interesting bit is `nlattr.NlAttrSchema`.

## Setup

Can by installed with usual Python package installation procedures. The
cleanest way is usually with [Pipenv](https://docs.pipenv.org/en/latest/):

- `sudo apt install python-pip  # Or equivalent for your OS`
- `pip install --user pipenv`
- `export PIPENV_VENV_IN_PROJECT=1  # Explained below`
- `cd <root directory of your application source code>`
- `pipenv install <root directory of this repository>`

#### If your application needs to be privileged

There are some complications if your application needs to run as root:
The above procedure installs the library in a virtualenv, which root 
will not automatically have access to. One way around this is to run 
your application via a `sudo` command that passes your user's Python
environment into the `sudo` environment:

- `pipenv shell`
- `sudo --preserve-env $(which python) <your app's entrypoint>`

The reason we exported `PIPENV_VENV_IN_PROJECT=1` above, then, 
helps you ensure that the root user has read permission on your
virtualenv files.     

If you are okay with modifying the target system's global 
configuration, a simpler alternative is to forego virtualenvs 
and install the library globally:

- `cd <root directory of this repository>`
- `sudo pip3 install .  # (Assuming you will be using Python 3, else use 'pip')`

## Running tests

- `pip install --user tox`
- `cd <root directory of this repository>`
- `tox`
