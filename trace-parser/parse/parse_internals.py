import sys
import os
import re
import pickle

api_call_entry_re = re.compile(r"^(.*)(ANDROID|JAVA)\s(\d{1,6})\s(S|E)\s(.*)$")
syscall_entry_re = re.compile(r"^(.*)SYSCALL\s([\d]{1,6})\s(.*)$")
db_filename = "db.pickle"
syscalls_list_filename = "syscall_list"

binder_ioctl_re = re.compile(r"^ioctl\([\d]+<\/dev\/.*binder>, BINDER_WRITE_READ.*$")

def load_db():
    if os.path.isfile(db_filename):
        with open(db_filename, "rb") as dbf:
            return pickle.load(dbf), pickle.load(dbf)
    return dict(), dict()

def store_db(db, syscalls):
    with open(db_filename, "wb") as dbf:
        pickle.dump(db, dbf)
        pickle.dump(syscalls, dbf)

def read_syscall_list():
    with open(syscalls_list_filename, "r") as slf:
        ret = slf.readlines()
        return [x.strip() for x in ret]

def parse_line(line):
    match = api_call_entry_re.match(line)
    if match is not None:
        (timestamp,_, tid, state, api) = match.groups()
        return (tid, "API", state, api, timestamp)
    else:
        match = syscall_entry_re.match(line)
        if match is None:
            print("Something went terribly wrong", file=sys.stderr)
            print("Line %s doesn't contain either a syscall nor an API call" %
                  line, file=sys.stderr)
            return (None, None, None, None)
        (timestamp, tid, syscall) = match.groups()
        return (tid, "SYS", None, syscall, timestamp)

def parse_line_convert(line):
    ret = parse_line(line)
    return (int(ret[0]), *ret[1:-1], float(ret[-1]))

def parsed_line_to_str(line):
    if line[1] == "API":
        return api_line_to_str(line)
    else:
        return sys_line_to_str(line)

def api_line_to_str(line):
    return "%f JAVA %d %c %s" % (line[-1], line[0], line[2], line[3])

def sys_line_to_str(line):
    return "%f SYSCALL %d %s" % (line[-1], line[0], line[2])
