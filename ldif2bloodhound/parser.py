from __future__ import annotations

import base64
import collections
import datetime
import logging
import os
import struct
from collections.abc import Generator
from pathlib import Path
from typing import Any

from ldif import LDIFParser
from requests.structures import CaseInsensitiveDict

log: logging.Logger = logging.getLogger(__name__)


class SeekableLDIFParser(LDIFParser):
    """This subclass of LDIFParser can build an index for random access

    This makes large LDIF files easier to handle. In this case, the parser
    needs a reference to the snapshot object. It will be passed to objects
    which are parsed from blocks, so they can access some extra information.
    (In particular the `category` property.)
    """

    def __init__(self, fp: Any, snapshot: LDIFSnapshot, **kwargs: Any) -> None:
        super().__init__(fp, **kwargs)
        self.snapshot: LDIFSnapshot = snapshot
        self._index: dict[str, int] = {}

    def build_index(self) -> None:
        """Build the index, which is a dict mapping the DN to the position in the file"""

        if self.byte_counter:
            raise RuntimeError("Index can only be built before first parsing")

        self._index = {}

        pos: int = 0
        for block in self._iter_blocks():
            first_line: bytes = block[0].partition(b"\n")[0]

            if first_line.startswith(b"dn: "):
                dn: str = first_line[4:].decode()
            elif first_line.startswith(b"dn:: "):
                dn = base64.b64decode(first_line[5:]).decode()
            else:
                raise RuntimeError(f"Parsing error at position {pos}")

            self._index[dn] = pos
            pos = self.byte_counter

        self._input_file.seek(0)

    def __getitem__(self, dn: str) -> Object:
        try:
            self._input_file.seek(self._index[dn])
        except AttributeError as err:
            raise RuntimeError("Index has not been built yet") from err

        block: list[bytes] = next(self._iter_blocks())
        result: Object = Object(self._parse_entry_record(block)[1], self.snapshot)

        return result

    def get_by_index(self, i: int) -> Object:
        key: str = list(self._index.keys())[i]
        return self[key]


class Object:
    """Represents an LDAP object

    Must be sufficiently compatible with ADExplorerSnapshot objects"""

    def __init__(self, data: dict[str, list[Any]], snapshot: LDIFSnapshot) -> None:
        self._data: CaseInsensitiveDict[Any] = CaseInsensitiveDict(data)
        self.snapshot: LDIFSnapshot = snapshot
        self.fix_attribute_types()

    def fix_attribute_types(self) -> None:
        """Everything is a string in LDIF, so convert as needed"""

        types: dict[str, type | Any] = {
            "userAccountControl": int,
            "sAMAccountType": int,
            "systemFlags": int,
            "adminCount": int,
            "whenCreated": convert_timestamp,
            "objectSid": convert_sid,
            "objectGUID": convert_GUID,
        }

        for attr, _type in types.items():
            if attr in self._data:
                self._data[attr] = list(map(_type, self._data[attr]))

    def _category(self) -> str | None:
        # copied mostly from ADExplorerSnapshot

        cat_dn: list[Any] = self.objectCategory
        if not cat_dn:
            return None

        cat_obj: Any = self.snapshot.classes.get(cat_dn[0])
        if cat_obj:
            return cat_obj.cn[0].lower()
        else:
            return None

    def __getattr__(self, attr: str) -> Any:
        # Quite hacky solution

        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError

        # This is a special attribute
        if attr == "category":
            return self._category()

        # ADExplorer sometimes uses different attribute names
        attr_map: dict[str, str] = {
            "classes": "objectClass",
            "schemaIDGUID": "objectGUID",
        }

        attr = attr_map.get(attr, attr)

        result: Any = self._data.get(attr, [])
        return result

    def __getitem__(self, key: str) -> CaseInsensitiveDict[Any]:
        # This object wants to be accessed like an ldap3 object:
        # object['attributes'][key]

        if key == "attributes":
            return self._data
        elif key == "raw_attributes":
            # Seems to work like this
            return self._data
        else:
            raise AttributeError


class LDIFSnapshot:
    """A class compatible with ADExplorerSnapshot's `Snapshot` class

    Requires two LDIF files: the base DN path is passed to __init__,
    the schema path must be set as a class attribute before instantiation:

        LDIFSnapshot.schema_path = Path("schema.ldif")
    """

    schema_path: Path | None = None

    def __init__(self, base_dn_path: Path, log: logging.Logger | None = None) -> None:
        if self.schema_path is None:
            raise ValueError("LDIFSnapshot.schema_path must be set before instantiation")

        fp_base = base_dn_path.open("rb")
        fp_schema = self.schema_path.open("rb")

        self._base_parser: SeekableLDIFParser = SeekableLDIFParser(fp_base, snapshot=self)
        self._schema_parser: SeekableLDIFParser = SeekableLDIFParser(fp_schema, snapshot=self)
        self._base_path: Path = base_dn_path
        self._base_count: int = 0
        self._schema_count: int = 0

    def parseHeader(self) -> None:
        self._base_parser.build_index()
        self._schema_parser.build_index()

        self._base_count = len(self._base_parser._index)
        self._schema_count = len(self._schema_parser._index)

        Header = collections.namedtuple(
            "Header",
            "metadataOffset filetimeUnix server mappingOffset numObjects filetime".split(),
        )

        # We don't know these things, they are not included in the LDIF
        # file, but the dependecy expects something here.
        filetime: float = self._base_path.stat().st_mtime
        path: str = str(self._base_path.resolve()).replace(os.sep, "_")
        self.header = Header(
            filetimeUnix=filetime,
            server="ldifdump" + path,
            mappingOffset=0,
            numObjects=self._base_count + self._schema_count,
            filetime=str(filetime),
            metadataOffset=0,
        )

    def parseProperties(self) -> None:
        # This is done in parseClasses in one loop
        pass

    def parseClasses(self) -> None:
        self.classes: CaseInsensitiveDict[Any] = CaseInsensitiveDict()
        self.propertyDict: CaseInsensitiveDict[Any] = CaseInsensitiveDict()
        self.properties: list[Object] = []

        for obj in self.objects:
            # Mimic the behavior of ADExplorerSnapshot
            if "classSchema" in obj.classes:
                cn: str = obj.cn[0]
                dn: str = obj.distinguishedName[0]

                self.classes[cn] = obj
                self.classes[dn] = obj
                self.classes[dn.split(",")[0].split("=")[1]] = obj

            if "attributeSchema" in obj.classes:
                cn = obj.cn[0]
                dn = obj.distinguishedName[0]

                idx: int = len(self.properties)
                self.properties.append(obj)
                #  abuse our dict for both DNs and the display name / cn
                self.propertyDict[cn] = idx
                self.propertyDict[dn] = idx
                self.propertyDict[dn.split(",")[0].split("=")[1]] = idx

    def parseObjectOffsets(self) -> None:
        # Not needed, we already have the offsets from `build_index`
        pass

    def getObject(self, i: int) -> Object:
        if i < self._base_count:
            return self._base_parser.get_by_index(i)
        return self._schema_parser.get_by_index(i - self._base_count)

    @property
    def objects(self) -> Generator[Object]:
        for i in range(self.header.numObjects):
            obj: Object = self.getObject(i)
            if obj:
                yield obj


def convert_GUID(guid: bytes) -> str:
    order: list[int] = [4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16]
    result: str = ""

    for i in order:
        result += f"{guid[i - 1]:x}"

    return result


def convert_timestamp(date: str) -> int:
    """Convert string to integer timestamp

    Example of input date: "20070828085401.0Z"
    """
    time_string: str = date.split(".")[0]
    time_object: datetime.datetime = datetime.datetime.strptime(time_string, "%Y%m%d%H%M%S")

    return int(time_object.timestamp())


def convert_sid(sid: str | bytes) -> str:
    """Converts a hexadecimal string returned from the LDAP query to a
    string version of the SID in format of S-1-5-21-1270288957-3800934213-3019856503-500
    This function was based from: http://www.gossamer-threads.com/lists/apache/bugs/386930

    Found here:
        https://gist.github.com/mprahl/e38a2eba6da09b2f6bd69d30fd3b749e
    This works better than the function from bloodhound.ad.utils. The former
    crashes on short SIDs such as S-1-5-32-553.
    """
    if isinstance(sid, str):
        sid = sid.encode()

    revision: int = sid[0]
    number_of_sub_ids: int = sid[1]

    # Identifier Authority Value (typically a value of 5 representing "NT Authority")
    # ">Q" is the format string. ">" specifies that the bytes are big-endian.
    # The "Q" specifies "unsigned long long" because 8 bytes are being decoded.
    # Since the actual SID section being decoded is only 6 bytes, we must precede it with 2 empty bytes.
    iav: int = struct.unpack(">Q", b"\x00\x00" + sid[2:8])[0]
    # The sub-ids include the Domain SID and the RID representing the object
    # '<I' is the format string. "<" specifies that the bytes are little-endian. "I" specifies "unsigned int".
    # This decodes in 4 byte chunks starting from the 8th byte until the last byte
    sub_ids: list[int] = [struct.unpack("<I", sid[8 + 4 * i : 12 + 4 * i])[0] for i in range(number_of_sub_ids)]

    return f"S-{revision}-{iav}-{'-'.join(str(sub_id) for sub_id in sub_ids)}"
