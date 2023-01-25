ldif2bloodhound
===============

Convert an LDIF file to JSON files ingestible by BloodHound.

The LDIF file should be retrieved like this with `ldapsearch`:

```console
$ for base in "" "CN=Schema,CN=Configuration," ; do \
    LDAPTLS_REQCERT=never ldapsearch \
    -H ldap://<DC> \
    -D <USERNAME>@corp.local \
    -w <PASSWORD> \
    -b "${base}DC=corp,DC=local" \
    -x \
    -o ldif-wrap=no \
    -E pr=1000/noprompt \
    -E '!1.2.840.113556.1.4.801=::MAMCAQc=' \
    -LLL \
    -ZZ \
    '(objectClass=*)' \
    ; done >> output_$(date +%s).ldif
```

The second `-E` argument is needed so that ACLs are also dumped.

Then, the conversion works as follows:

```console
$ ldif2bloodhound output_*.ldif
```

For more options, run `ldif2bloodhound --help`.


Installation
------------

Install with this command:

```console
$ pip install git+https://github.com/SySS-Research/ldif2bloodhound
```

Copyright and License
---------------------

SySS GmbH, Adrian Vollmer. MIT Licensed.
