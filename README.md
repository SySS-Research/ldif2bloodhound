ldif2bloodhound
===============

Convert LDIF files to JSON files ingestible by BloodHound.

Two separate LDIF files are required: one for the base DN and one for the
schema tree. Retrieve them with `ldapsearch` like this:

```console
$ LDAP_OPTS="-H ldap://<DC> -D <USERNAME>@corp.local -w <PASSWORD> -x \
    -o ldif-wrap=no -E pr=1000/noprompt \
    -E '!1.2.840.113556.1.4.801=::MAMCAQc=' -LLL -ZZ"

$ LDAPTLS_REQCERT=never ldapsearch $LDAP_OPTS \
    -b "DC=corp,DC=local" '(objectClass=*)' > base_dn.ldif

$ LDAPTLS_REQCERT=never ldapsearch $LDAP_OPTS \
    -b "CN=Schema,CN=Configuration,DC=corp,DC=local" '(objectClass=*)' > schema.ldif
```

In case StartTLS does not work, remove the `-ZZ` flag and replace
`ldap://` with `ldaps://`. Or leave it at `ldap://` if you like to live
dangerously.

The second `-E` argument is needed so that ACLs are also dumped.

Then, the conversion works as follows:

```console
$ ldif2bloodhound base_dn.ldif schema.ldif
```

For more options, run `ldif2bloodhound --help`.

The obvious limitation is that you won't get information about sessions or
local group memberships, just like with
[ADExplorerSnapshot.py](https://github.com/c3c/ADExplorerSnapshot.py).
Parsing LDIF data is more equivalent to running SharpHound with `-c DCOnly`
(perhaps even less).
[BloodHound.py](https://github.com/fox-it/BloodHound.py) is a better choice
to collect this data in most scenarios.

Installation
------------

Install with this command:

```console
$ uv tool install git+https://github.com/SySS-Research/ldif2bloodhound
# Alternatively:
$ pipx install git+https://github.com/SySS-Research/ldif2bloodhound
```

Copyright and License
---------------------

SySS GmbH, Adrian Vollmer. MIT Licensed.
