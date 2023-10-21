import sys
import csv
import re
import itertools
from pathlib import Path
from timeit import default_timer as timer
import argparse

def nullog(*args):
    return

def log2file(*args):
    global logfilename
    with open(logfilename, 'a') as f:
        for a in args:
            f.write(str(a))
            f.write(' ')
        f.write('\n')

class RegExNode:
    def __init__(self, raw_regex):
        self.num_matches = 0
        self.compiled_regex = re.compile(raw_regex)
        self.output_print = []
        self._raw_regex = raw_regex

    @property
    def raw_regex(self):
        return self._raw_regex

    def kill_on_match(self, di):
        # yes, the regex.search() may be called on a pruned domain between the
        # check for alive and match. this is ok as killing twice is harmelss.
        # the only waste is a domain was checked by two regexes. unlikely that a
        # 3rd regex would check the same domain. domains will only ever change
        # from "alive and well" to "dead".
        if di.alive_and_well and self.compiled_regex.search(di.domain):
            di.kill = None
            self.output_print.append(["killed matched %s\n" % di.domain])
            self.num_matches += 1
            pass

    def output(self, p):
        self.output_print.append(p)

    def synopsis(self, t_name):
        return self.output_print + \
                [["regex %s" % self.compiled_regex],
                 ["\tremoved:", self.num_matches]]

class DomainPointer:
    def __init__(self, csv_row, file_row):
        self._domain = csv_row[1]
        self._listname = csv_row[4]
        self._match_strength = 0 if len(csv_row) < 7 else \
                int(csv_row[6])

        self._rev_domain = self._domain.split('.')
        self.iter_subdomains = reversed(self._rev_domain)
        self._file_row = file_row
        self._alive_and_well = True

    def next_tld(self):
        try:
            return next(self.iter_subdomains)
        except StopIteration:
            return None

    @property
    def file_row(self):
        return self._file_row

    @property
    def match_strength(self):
        return self._match_strength

    @property
    def domain(self):
        return self._domain

    @property
    def listname(self):
        return self._listname

    @property
    def alive_and_well(self):
        return self._file_row != -1

    @alive_and_well.setter
    def kill(self, _):
        self._file_row = -1

class DomainInfo:
    def __init__(self, csv_row, _):
        self.csv_row = csv_row
        self._rev_domain = self.domain.split('.')
        self.iter_subdomains = reversed(self._rev_domain)
        self._alive_and_well = True

    def next_tld(self):
        try:
            return next(self.iter_subdomains)
        except StopIteration:
            return None

    @property
    def match_strength(self):
        return 0 if len(self.csv_row) < 7 else int(self.csv_row[6])

    @property
    def domain(self):
        return self.csv_row[1]

    @property
    def file_row(self):
        return self.csv_row

    @property
    def listname(self):
        return self.csv_row[4]

    @property
    def alive_and_well(self):
        return self._alive_and_well

    @alive_and_well.setter
    def kill(self, _):
        log("killed:", self.domain)
        self._alive_and_well = False

class DomainTree:
    def __init__(self, tld=None, di=None):
        self.children = {}
        self.tld = tld
        self.di = None
        self.is_root = self.tld is None and di is None

        if self.is_root:
            return

        next_tld = di.next_tld()
        if next_tld is not None:
            self.children[next_tld] = DomainTree(next_tld, di)
        else:
            # children is empty which means it is a leaf
            self.di = di

    @property
    def is_leaf(self):
        return len(self.children) == 0

    def visit_leaves(self, visitor):
        for c in self.children.values():
            if c.di is not None and c.di.alive_and_well:
                visitor(c.di)
            c.visit_leaves(visitor)

    def insert(self, di):
        next_tld = di.next_tld()
        if next_tld is not None:
            c = self.children.get(next_tld)
            if c is not None:
                if c.is_leaf:
                    if c.di.match_strength == 1:
                        return False

                    if c.di.domain == di.domain:
                        if di.match_strength == 1:
                            #print("overwrite: c is weaker than di:")
                            #print("\t", c.csv_row)
                            #print("\t", di.csv_row)
                            c.di = di
                            return True
                        else:
                            return False

                return c.insert(di)

            # didn't find a matching subdomain
            #print("overwrite children of tld:", next_tld)
            #print("len of children pruned:", len(self.children))
            self.children[next_tld] = DomainTree(next_tld, di)
            return True

        # e.g. di is google.com and self.tld is 'google'
        # we have a duplicate. is this 'di' stronger than self?
        else:
            # we have reached a case where the incoming 'di' is at a terminus.
            # there is no deeper levels to go. if it is a strong match and
            # self.di is None i.e. self is not a leaf or a terminous, then we
            # can make self a terminal and be done.
            if self.di is None:
                if di.match_strength == 1:
                    #for k in self.children.keys():
                        #print("for: self is None, di is strong: purging all children of:", k)
                    #print("self is None, di is strong: purging all children of:", k)
                    #print("len of children pruned:", len(self.children))
                    self.children = {}
                    #self.di = di
                #else: # di.match_strength == 0:
                    #self.di = di
                self.di = di
                return True

            # there might be children since middle ware things can now have a
            # greater strength match and not be a leaf. clear children as they
            # are obliterated.
            #assert(self.di is not None)
            if self.di.match_strength < di.match_strength:
                self.di = di
                #for k in self.children.keys():
                    #print("for: self weaker than di: purging all children of:", k)
                #print("self weaker than di: purging all children of:", k)
                #print("len of children pruned:", len(self.children))
                self.children = {}
                return True

        return False

def _skip_regex_matches():
    pass

def _prune_regex_matches():
    global domainTree, regexNodes
    for regex in regexNodes:
        domainTree.visit_leaves(lambda x: regex.kill_on_match(x))

def read_csv(filename, outputfile):
    global domainTree, regexNodes
    inserted_cnt = 0
    omitted_cnt = 0
    ignored_cnt = 0
    regexlines = 0
    cur_row_idx = -1

    log("Enter read_csv() with args:", filename, outputfile)

    with (open(filename, 'r', newline='') as csvinfile,
            open(outputfile, 'w', newline='') as csvoutfile):
        pfb_py_reader = csv.reader(csvinfile, delimiter=',')
        pfb_py_writer = csv.writer(csvoutfile, delimiter=',',
                quotechar="'", lineterminator='\n')
        for cur_row_idx, row in enumerate(pfb_py_reader):
            if not (len(row) == 7 or len(row) == 6):
                ignored_cnt += 1
                log("NOTE: Ignoring row with %s columns" % len(row), row)
                continue

            # 7th column is 0, 1 or 2
            match_strength = int(row[6]) if len(row) == 7 else 0
            if not (match_strength >= 0 or match_strength <= 2):
                ignored_cnt += 1
                log("NOTE: Ignoring row with unrecognized value for 7th column: %d (expected >= 0 and <= 2)" % match_strength)
                continue

            if match_strength < 2:
                di = DomainType(row, cur_row_idx)
                if domainTree.insert(di):
                    inserted_cnt += 1
                else:
                    omitted_cnt += 1
                    log("Pruned:", row)
            else:
                # do not modify the regex rows
                pfb_py_writer.writerow(row)
                regexNodes.append(RegExNode(row[1]))
                regexlines += 1

    linesread = (cur_row_idx + 1) - ignored_cnt
    log("\tProcessed %s and found %d row%s of which %d %s regex." % \
            (filename, linesread, '' if linesread == 1 else 's', \
                regexlines, 'is a' if regexlines == 1 else 'are'))
    log("\tInserted %s possibly unique entr%s and omitted %d confirmed duplicate%s.\n" \
            % (inserted_cnt, 'y' if inserted_cnt == 1 else 'ies', \
                omitted_cnt, '' if omitted_cnt == 1 else 's'))
    log("\tIgnored %s line%s. Ideally this number is zero. If not, inspect input files for bogus data.\n" \
            % (ignored_cnt, '' if ignored_cnt == 1 else 's'))

    # read more than one line: queue for pruning.
    return linesread - regexlines > 0

class CsvReaders:
    def __init__(self, filenames):
        self.filenames = filenames
        self.filehandles = []
        self.csvreaders = {}


    def __enter__(self):
        for fn in self.filenames.keys():
            self.filehandles.append(open(self.filenames[fn], 'r', newline=''))
            self.csvreaders[fn] = [csv.reader(self.filehandles[-1], delimiter=','), 0]
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for f in self.filehandles:
            f.close()

    def readline(self, fn, seek_line):
        (f, next_line) = self.csvreaders[fn]

        while seek_line != next_line:
            next(f)
            next_line += 1

        self.csvreaders[fn][1] = next_line + 1
        return next(f)

class CsvWriters:
    def __init__(self, filenames):
        self.filenames = filenames
        self.filehandles = []
        self.csvwriters = {}

    def __enter__(self):
        for fn in self.filenames.keys():
            # append is utilized here b/c regexes, if any, were written to
            # the '*.pruned' file during the initial read.
            self.filehandles.append(open(self.filenames[fn], 'a', newline=''))
            # note: only the filename is ued for the dict key.
            self.csvwriters[fn] = csv.writer(self.filehandles[-1], delimiter=',',
                    quotechar="'", lineterminator='\n')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for f in self.filehandles:
            f.close()

    def write(self, listname, csv_row):
        try:
            csvwriter = self.csvwriters[listname]
            csvwriter.writerow(csv_row)
        except KeyError:
            log("csv writer for '%s' was not found!" % listname)

def write_DomainInfos(files_to_read, files_to_write, out_ext):
    global domainTree

    log("Writing pruned contents to '*%s' files..." % out_ext)
    with CsvWriters(files_to_write) as csvwriters:
        def visitor(x):
            if x.alive_and_well:
                csvwriters.write(x.listname, x.csv_row)
        domainTree.visit_leaves(lambda x: visitor(x))

def write_DomainPointers(files_to_read, files_to_write, out_ext):
    global domainTree

    file_refs = dict((fn, []) for fn in files_to_read.keys())

    def visitor(x):
        if x.alive_and_well:
            file_refs[x.listname].append(x.file_row)

    domainTree.visit_leaves(lambda x: visitor(x))

    log("Writing pruned contents to '*%s' files..." % out_ext)
    with (CsvWriters(files_to_write) as csvwriters,
            CsvReaders(files_to_read) as readers):
        for fn in file_refs.keys():
            for i in sorted(file_refs[fn]):
                csvwriters.write(fn,
                        readers.readline(fn, i))

def process_directory(dirpath, in_ext, out_ext):
    global domainTree, iter_regexnodes
    files_to_write = {}
    files_to_read = {}

    # expecting to have a small set of files to iterate over
    for p in sorted(dirpath.glob('*' + in_ext)):
        fname = p.name[:-len(in_ext)]
        prunedfile = fname + out_ext
        log("Found a '*%s' file to read:" % in_ext, p.name)

        # building the tree prunes of duplicates by the 'match strength' for
        # match strengths equal to '1' which is "Adblock Plus" full domain and
        # subdomain block. regex, match strength equal to '2' is done before
        # 'write_csv'
        if read_csv(str(p.absolute()), str(p.parent / prunedfile)):
            files_to_write[fname] = str(p.parent / prunedfile)
            files_to_read[fname] = str(p)

    prune_regex_matches()

    if len(files_to_read) and len(files_to_write):
        write_csv(files_to_read, files_to_write, out_ext)


domainTree = DomainTree()
regexNodes = []
log = nullog
dataHandlers = {'pointer': (DomainPointer, write_DomainPointers),
                'standard': (DomainInfo, write_DomainInfos)}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Directory containing input "
            "files, input extensions, output extensions and optional options")

    parser.add_argument("directory", type=str,
            help="Directory holding '.txt' files to prune and write to '.pruned' files")

    parser.add_argument("--method", type=str, nargs='?', default='pointer',
            help="Method of pruning: 'standard' or 'pointer'")

    parser.add_argument("in_ext", type=str, nargs='?', default='.txt',
            help="Input extension; default is '.txt'")

    parser.add_argument("out_ext", type=str, nargs='?', default='.pruned',
            help="Output extension; default is '.pruned'")

    parser.add_argument("--prune-regex", action="store_true",
            help="Prune domains matching regexes found in the input files")

    parser.add_argument("--log", type=str, nargs='?',
            const='./pfb_dnsbl_prune.log', default=None,
            help="Enable log; default is './pfb_dnsbl_prune.log'")

    args = parser.parse_args()

    print('in ext:', args.in_ext)
    print('prune regex:', args.prune_regex)
    print('method:', args.method)
    print('log:', args.log)
    print('directory:', args.directory)

    directory = Path(args.directory)

    if not directory.is_dir():
        parser.error("Specify an existing directory")

    if len(args.in_ext) < 2 or args.in_ext[0] != '.':
        parser.error("Input extension must start with a period and have at least one character")
    if len(args.out_ext) < 2 or args.out_ext[0] != '.':
        parser.error("Output extension must start with a period and have at least one character")
    if args.in_ext == args.out_ext:
        parser.error("Input extension must differ from Output extension")

    if args.method not in dataHandlers:
        parser.error("Method must be 'pointer' or 'standard'")

    if args.log is not None:
        logfilename = args.log
        log = log2file

    (DomainType, write_csv) = dataHandlers[args.method]

    prune_regex_matches = _prune_regex_matches if args.prune_regex else _skip_regex_matches
    log("Trim '*%s' files in '%s' and write as '*%s'." \
            % (args.in_ext, args.directory, args.out_ext))

    log("Begin processing directory:", args.directory)
    start = timer()
    process_directory(directory, args.in_ext, args.out_ext)
    end = timer()
    log("Processing completed in:", end - start)
