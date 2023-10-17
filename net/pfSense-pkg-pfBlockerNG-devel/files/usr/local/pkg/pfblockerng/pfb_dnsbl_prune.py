import sys
import csv
from pathlib import Path
from timeit import default_timer as timer

def nullog(*args):
    return

def log2file(*args):
    global logfilename
    with open(logfilename, 'a') as f:
        for a in args:
            f.write(str(a))
            f.write(' ')
        f.write('\n')

class DomainPointer:
    def __init__(self, csv_row, file_row):
        self._domain = csv_row[1]
        self._listname = csv_row[4]
        self._match_strength = 0 if len(csv_row) < 7 else \
                int(csv_row[6])

        self._rev_domain = self._domain.split('.')
        self.iter_subdomains = reversed(self._rev_domain)
        self._file_row = file_row

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

class DomainInfo:
    def __init__(self, csv_row, _):
        self.csv_row = csv_row
        self._rev_domain = self.domain.split('.')
        self.iter_subdomains = reversed(self._rev_domain)

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
            if c.di is not None:
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

def read_csv(filename, outputfile):
    global domainTree
    regexlines = 0
    inserted_cnt = 0
    omitted_cnt = 0
    ignored_cnt = 0

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

def write_DomainInfos(files_to_read, files_to_write):
    global domainTree

    log("Writing pruned contents to '*%s' files..." % out_ext)
    with CsvWriters(files_to_write) as csvwriters:
        def visitor(di):
            csvwriters.write(di.listname, di.file_row)
        domainTree.visit_leaves(lambda x: visitor(x))

def write_DomainPointers(files_to_read, files_to_write):
    global domainTree

    file_refs = dict((fn, []) for fn in files_to_read.keys())

    def visitor(x):
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
    files_to_write = {}
    files_to_read = {}

    # expecting to have a small set of files to iterate over
    for p in sorted(dirpath.glob('*' + in_ext)):
        fname = p.name[:-len(in_ext)]
        prunedfile = fname + out_ext
        log("Found a '*%s' file to read:" % in_ext, p.name)

        if read_csv(str(p.absolute()), str(p.parent / prunedfile)):
            files_to_write[fname] = str(p.parent / prunedfile)
            files_to_read[fname] = str(p)

    if len(files_to_read) and len(files_to_write):
        write_csv(files_to_read, files_to_write)


domainTree = DomainTree()
log = nullog
dataHandlers = {'pointer': (DomainPointer, write_DomainPointers),
                'standard': (DomainInfo, write_DomainInfos)}
DomainType = DomainPointer
write_csv = write_DomainPointers

if __name__ == '__main__':
    in_ext = '.txt'
    out_ext = '.pruned'
    logfilename = './pfb_dnsbl_prune.log'

    num_args = len(sys.argv)

    if num_args < 2:
        log("Specify a directory containing csv files with .fat extension to be pruned.")
        sys.exit(1)

    directory = Path(sys.argv[1])

    if not directory.is_dir():
        log("Specify an existing directory.")
        sys.exit(1)

    if num_args > 2:
        in_ext = sys.argv[2]
        if len(in_ext) < 2:
            log("Input extension must be at least two characters, e.g., '.F'")

    if num_args > 3:
        out_ext = sys.argv[3]

    if num_args > 4 and (sys.argv[4] == 'standard' or sys.argv[4] == 'pointer'):
        (DomainType, write_csv) = dataHandlers[sys.argv[4]]

    log("Trim '*%s' files in '%s' and write as '*%s'." \
            % (in_ext, directory, out_ext))

    if num_args > 5 and len(sys.argv[5]) > 0:
        logfilename = sys.argv[5]
        log = log2file

    log("Begin processing directory:", directory)
    start = timer()
    process_directory(directory, in_ext, out_ext)
    end = timer()
    log("Processing completed in:", end - start)
