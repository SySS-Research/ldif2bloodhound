import base64
import collections
import logging
import os
from requests.structures import CaseInsensitiveDict
import struct
import sys

from ldif import LDIFParser

log = logging.getLogger(__name__)


class SeekableLDIFParser(LDIFParser):
    """This subclass of LDIFParser can build an index for random access

    This makes it large LDIF files easier to handle. In this case, the
    parser needs a reference to the snapshot object so it can access some
    extra information.
    """

    def __init__(self, fp, snapshot, **kwargs):
        super().__init__(fp, **kwargs)
        self.snapshot = snapshot

    def build_index(self):
        """Build the index, which is a dict mapping the DN to the position in the file"""

        if self.byte_counter:
            raise RuntimeError("Index can only be built before first parsing")

        self._index = {}  # Assumed to be OrderedDict

        pos = 0
        for block in self._iter_blocks():
            first_line = block[0].partition(b'\n')[0]

            if first_line.startswith(b'dn: '):
                dn = first_line[4:].decode()
            elif first_line.startswith(b'dn:: '):
                dn = first_line[5:]
                dn = base64.b64decode(dn).decode()
            else:
                raise RuntimeError("Parsing error at position %d" % pos)

            self._index[dn] = pos
            pos = self.byte_counter

        self._input_file.seek(0)

    def __getitem__(self, dn):
        try:
            self._input_file.seek(self._index[dn])
        except AttributeError:
            raise RuntimeError("Index has not been built yet")

        block = next(self._iter_blocks())
        result = Object(self._parse_entry_record(block)[1], self.snapshot)

        return result

    def get_by_index(self, i):
        key = list(self._index.keys())[i]
        return self[key]


class Object(object):
    """Represents an LDAP object

    Must be sufficiently compatible with ADExplorerSnapshot objects"""

    def __init__(self, data, snapshot):
        self._data = CaseInsensitiveDict(data)
        self.snapshot = snapshot
        self.fix_attribute_types()

    def fix_attribute_types(self):
        """Everything is a string in LDIF, so convert as needed"""

        types = {
            'userAccountControl': int,
            'sAMAccountType': int,
            'systemFlags': int,
            'adminCount': int,
            'whenCreated': convert_timestamp,
            'objectSid': convert_sid,
            'objectGUID': convert_GUID,
        }

        for attr, _type in types.items():
            if attr in self._data:
                self._data[attr] = list(map(_type, self._data[attr]))

    def _category(self):
        catDN = self.objectCategory
        if not catDN:
            return None

        catDN = catDN[0]
        catObj = self.snapshot.classes.get(catDN)
        if catObj:
            return catObj.cn[0].lower()
        else:
            return None

    def __getattr__(self, attr):
        # Quite hacky solution

        if attr.startswith('__') and attr.endswith('__'):
            raise AttributeError

        # This is a special attribute; copy from ADExplorerSnapshot
        if attr == 'category':
            return self._category()

        # ADExplorer sometimes uses different attribute names
        attr_map = {
            'classes': 'objectClass',
            'schemaIDGUID': 'objectGUID',
        }

        attr = attr_map.get(attr, attr)

        result = self._data.get(attr, [])
        return result

    def __getitem__(self, key):
        # This object wants to be accessed like an ldap3 object:
        # object['attributes']['key']

        if key == 'attributes':
            return self._data
        elif key == 'raw_attributes':
            # Seems to work like this
            return self._data
        else:
            raise AttributeError


class LDIFSnapshot(object):
    """A class compatible with ADExplorerSnapshot's `Snapshot` class"""

    def __init__(self, path, log=None):
        fp = open(path, 'rb')
        self._P = SeekableLDIFParser(fp, snapshot=self)
        self.path = path

    def parseHeader(self):
        self._P.build_index()
        Header = collections.namedtuple(
            'Header',
            'filetimeUnix server mappingOffset numObjects filetime'.split(),
        )

        # We don't know these things, they are not included in the LDIF file
        self.header = Header(
            filetimeUnix=os.path.getmtime(self.path),
            server='ldifdump',
            mappingOffset=0,
            numObjects=len(self._P._index),
            filetime='',
        )

    def parseProperties(self):
        # This is done in parseClasses in one loop
        pass

    def parseClasses(self):
        self.classes = CaseInsensitiveDict()
        self.propertyDict = CaseInsensitiveDict()
        self.properties = []

        for obj in self.objects:
            # Objects need to know about classes for `category` property
            obj._classes = self.classes

            # Mimic the behavior of ADExplorerSnapshot
            if 'classSchema' in obj.classes:
                cn = obj.cn[0]
                dn = obj.distinguishedName[0]

                self.classes[cn] = obj
                self.classes[dn] = obj
                self.classes[dn.split(',')[0].split('=')[1]] = obj

            if 'attributeSchema' in obj.classes:
                cn = obj.cn[0]
                dn = obj.distinguishedName[0]

                #  prop = Property(self, in_obj)
                idx = len(self.properties)
                self.properties.append(obj)
                #  abuse our dict for both DNs and the display name / cn
                self.propertyDict[cn] = idx
                self.propertyDict[dn] = idx
                self.propertyDict[dn.split(',')[0].split('=')[1]] = idx

    def parseObjectOffsets(self):
        # Not needed, we already have the offsets from `build_index`
        pass

    def getObject(self, i):
        obj = self._P.get_by_index(i)
        return obj

    @property
    def objects(self):
        for i in range(self.header.numObjects):
            obj = self.getObject(i)
            if obj:
                yield obj


def convert_GUID(guid):
    order = [4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16]
    result = ''

    for i in order:
        result += '%x' % guid[i-1]

    return result


def convert_timestamp(date):
    """Convert string to integer timestamp

    Example of input date: "20070828085401.0Z"
    """
    import datetime

    time_string = date.split('.')[0]
    time_object = datetime.datetime.strptime(time_string, "%Y%m%d%H%M%S")
    time_object = int(time_object.timestamp())

    return time_object


def convert_sid(sid):
    """ Converts a hexadecimal string returned from the LDAP query to a
    string version of the SID in format of S-1-5-21-1270288957-3800934213-3019856503-500
    This function was based from: http://www.gossamer-threads.com/lists/apache/bugs/386930

    Found here:
        https://gist.github.com/mprahl/e38a2eba6da09b2f6bd69d30fd3b749e
    This works better than the function from bloodhound.ad.utils. The former
    crashes on short SIDs such as S-1-5-32-553.
    """
    if isinstance(sid, str):
        sid = sid.encode()
    # The revision level (typically 1)
    if sys.version_info.major < 3:
        revision = ord(sid[0])
    else:
        revision = sid[0]
    # The number of dashes minus 2
    if sys.version_info.major < 3:
        number_of_sub_ids = ord(sid[1])
    else:
        number_of_sub_ids = sid[1]
    # Identifier Authority Value (typically a value of 5 representing "NT Authority")
    # ">Q" is the format string. ">" specifies that the bytes are big-endian.
    # The "Q" specifies "unsigned long long" because 8 bytes are being decoded.
    # Since the actual SID section being decoded is only 6 bytes, we must precede it with 2 empty bytes.
    iav = struct.unpack('>Q', b'\x00\x00' + sid[2:8])[0]
    # The sub-ids include the Domain SID and the RID representing the object
    # '<I' is the format string. "<" specifies that the bytes are little-endian. "I" specifies "unsigned int".
    # This decodes in 4 byte chunks starting from the 8th byte until the last byte
    sub_ids = [struct.unpack('<I', sid[8 + 4 * i:12 + 4 * i])[0]
               for i in range(number_of_sub_ids)]

    return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([
        str(sub_id)
        for sub_id in sub_ids
    ]))
