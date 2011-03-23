import cPickle
from slavealloc.data import model, setup

def setup_argparse(subparsers):

    subparser = subparsers.add_parser('dbinit', help="""Initialize a fresh
            database, optionally from a dump file.  Note that this does not use
            the REST API, but writes to the database directly.""")

    subparser.add_argument('-D', '--db', dest='dburl',
            default='sqlite:///slavealloc.db',
            help="""SQLAlchemy database URL; defaults to slavealloc.db in the
            current dir""")

    subparser.add_argument('dumpfile', nargs='?',
            help="""dump file as generated by 'slavealloc dbdump'; if not
            specified, then an empty database will be initialized.""")

    return subparser

def process_args(subparser, args):
    pass

def main(args):
    setup.setup(args.dburl)

    model.metadata.drop_all()
    model.metadata.create_all()

    if args.dumpfile:
        load_data(args)

def load_data(args):
    # see dbdump.py for the data format here
    dumpdict = cPickle.load(open(args.dumpfile))
    for tbl in model.metadata.sorted_tables:
        tname = tbl.name
        tbl = model.metadata.tables[tname]
        tbl.insert().execute(dumpdict[tname])
