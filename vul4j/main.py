import argparse
import os.path
import subprocess
import sys
from datetime import datetime

from loguru import logger

import vul4j.spotbugs as spotbugs
import vul4j.evaluator as evaluator
import vul4j.utils as utils
import vul4j.vul4j_tools as vul4j
from vul4j.config import VUL4J_DATA, FILE_LOG_LEVEL, LOG_TO_FILE


# logger
def setup_logger(command: str, display_level: str = "INFO", file_level: str = "DEBUG"):
    log_filename = f"{datetime.now().strftime('%y%m%d_%H%M%S')}_{command}_{file_level}.log"
    log_dir = os.path.join(VUL4J_DATA, "logs")
    logger.remove()
    logger.add(sys.stdout,
               colorize=True,
               format="<cyan>{time:YYYY-MM-DD HH:mm:ss}</cyan> | <level>{message}</level>",
               diagnose=False,
               backtrace=False,
               level=display_level.upper())
    if LOG_TO_FILE and os.path.isdir(log_dir):
        logger.add(os.path.join(log_dir, log_filename),
                   format="<cyan>{time:YYYY-MM-DD HH:mm:ss}</cyan> | <level>{level}</level> | <level>{message}</level>",
                   rotation="00:00",
                   level=file_level.upper())


@utils.log_frame("INIT")
def vul4j_init(args):
    utils.init_data_dir(args.location)


@utils.log_frame("STATUS")
def vul4j_status(_):
    utils.check_status()


@utils.log_frame("CHECKOUT")
def vul4j_checkout(args):
    vul4j.checkout(args.id, args.outdir, args.force)


@utils.log_frame("COMPILE")
def vul4j_compile(args):
    try:
        vul4j.build(args.outdir, clean=args.clean)
    except subprocess.CalledProcessError:
        raise RuntimeError("Compile failed!")


@utils.log_frame("TEST")
def vul4j_test(args):
    try:
        vul4j.test(args.outdir, args.batchtype, clean=args.clean)
    except subprocess.CalledProcessError:
        raise RuntimeError("Testing failed!")


@utils.log_frame("APPLY")
def vul4j_apply(args):
    vul4j.apply(args.outdir, args.version)


@utils.log_frame("SAST")
def vul4j_sast(args):
    versions = args.versions
    output_dir = args.outdir
    force = args.force

    versions = versions if versions else [None]

    for version in versions:
        if version:
            if version != versions[0]:
                logger.info(utils.SEPARATOR)
            logger.info(f"Checking version: {version}...")
            vul4j.apply(output_dir, version, True)

        try:
            spotbugs.run_spotbugs(output_dir, version, bool(version) or force)
        except subprocess.CalledProcessError:
            # compile, method getter or spotbugs fails
            logger.error("Task failed!")
            continue
        except (vul4j.VulnerabilityNotFoundError, AssertionError) as err:
            # any file fails to be created or the correct jar was not found
            logger.error(err)
            continue


@utils.log_frame("REPRODUCE")
def vul4j_reproduce(args):
    vul4j.reproduce(args.id)


@utils.log_frame("INFO")
def vul4j_info(args):
    vul4j.get_info(args.id)


@utils.log_frame("CLASSPATH")
def vul4j_classpath(args):
    vul4j.classpath(args.outdir)


@utils.log_frame("GET-SPOTBUGS")
def get_spotbugs(args):
    utils.get_spotbugs(args.location)


@utils.log_frame("EVALUATE")
def vul4j_evaluate(args):
    if args.keep_checkouts:
        os.environ["KEEP_CHECKOUTS"] = "1"
    evaluator.VUL4JEvaluator(
        input_file=args.input_file,
        output_file=args.output,
        work_dir=args.work_dir,
        output_dir=args.output_dir,
        only=args.id,
        apply_only=args.apply_only,
    ).run()


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(prog="vul4j", description="A Dataset of Java vulnerabilities.")
    parser.add_argument('-l', '--log', type=str, default="INFO",
                        help="Specify displayed log level for this command.")

    sub_parsers = parser.add_subparsers()

    # INIT
    init_parser = sub_parsers.add_parser("init",
                                         help="Create the Vul4J data directory and default config.")
    init_parser.add_argument("--location", type=str,
                             help="Custom data directory. Set VUL4J_DATA to the same path for later commands.",
                             required=False)
    init_parser.set_defaults(func=vul4j_init, requires_config=False)

    # STATUS
    status_parser = sub_parsers.add_parser("status",
                                           help="Lists vul4j requirements and their availability.")
    status_parser.set_defaults(func=vul4j_status)

    # CHECKOUT
    checkout_parser = sub_parsers.add_parser('checkout',
                                             help="Checkout a vulnerability into the specified directory.")
    checkout_parser.add_argument("-i", "--id", type=str,
                                 help="Vulnerability ID.", required=True)
    checkout_parser.add_argument("-d", "--outdir", type=str,
                                 help="The destination directory.", required=True)
    checkout_parser.add_argument("-f", "--force", action="store_true",
                                 help="Removes the destination directory if it already exists.")
    checkout_parser.set_defaults(func=vul4j_checkout)

    # COMPILE
    compile_parser = sub_parsers.add_parser('compile',
                                            help="Compile the checked out vulnerability.")
    compile_parser.add_argument("-d", "--outdir", type=str,
                                help="The directory to which the vulnerability was checked out.", required=True)
    compile_parser.add_argument("-c", "--clean", action="store_true",
                                help="Clean the project before compiling.")
    compile_parser.set_defaults(func=vul4j_compile)

    # TEST
    test_parser = sub_parsers.add_parser('test',
                                         help="Run testsuite for the checked out vulnerability.")
    test_parser.add_argument("-d", "--outdir", type=str,
                             help="The directory to which the vulnerability was checked out.", required=True)
    test_parser.add_argument("-b", "--batchtype", choices=["povs", "all"], default="all", type=str,
                             help="Two modes: all tests (all) by default, and only povs (povs).", required=False)
    test_parser.add_argument("-c", "--clean", action="store_true",
                             help="Clean the project before compiling.")
    test_parser.set_defaults(func=vul4j_test)

    # APPLY
    apply_parser = sub_parsers.add_parser('apply',
                                          help="Apply the specified file versions.")
    apply_parser.add_argument("-d", "--outdir", type=str,
                              help="The directory to which the vulnerability was checked out.", required=True)
    apply_parser.add_argument("-v", "--version", type=str,
                              help="Version to apply.", required=True)
    apply_parser.set_defaults(func=vul4j_apply)

    # SAST
    sast_parser = sub_parsers.add_parser('sast',
                                         help="Run Spotbugs analysis.")
    sast_parser.add_argument("-d", "--outdir", type=str,
                             help="The directory to which the vulnerability was checked out.", required=True)
    sast_parser.add_argument("-v", "--versions", nargs='+',
                             help="Versions to run spotbugs on.", required=False)
    sast_parser.add_argument("-f", "--force", action="store_true",
                             help="Force recompile project.")
    sast_parser.set_defaults(func=vul4j_sast)

    # REPRODUCE
    reproduce_parser = sub_parsers.add_parser('reproduce', aliases=["verify"],
                                              help="Verify the reproducibility of vulnerabilities in the dataset.")
    reproduce_parser.add_argument("-i", "--id", nargs='+', type=str,
                                  help="Vulnerability ID.", required=True)
    reproduce_parser.set_defaults(func=vul4j_reproduce)

    # INFO
    info_parser = sub_parsers.add_parser('info',
                                         help="Print information about a vulnerability.")
    info_parser.add_argument("-i", "--id", type=str,
                             help="Vulnerability ID.", required=True)
    info_parser.set_defaults(func=vul4j_info)

    # CLASSPATH
    cp_parser = sub_parsers.add_parser('classpath',
                                       help="Print the classpath of the checked out vulnerability.")
    cp_parser.add_argument("-d", "--outdir", type=str,
                           help="The directory to which the vulnerability was checked out.", required=True)
    cp_parser.set_defaults(func=vul4j_classpath)

    # GET SPOTBUGS
    spotbugs_parser = sub_parsers.add_parser("get-spotbugs",
                                             help="Download Spotbugs into the user directory.")
    spotbugs_parser.add_argument("-l", "--location", type=str,
                                 help="Custom spotbugs installation path.", required=False)
    spotbugs_parser.set_defaults(func=get_spotbugs)

    # EVALUATE
    evaluate_parser = sub_parsers.add_parser("evaluate",
                                             help="Evaluate candidate patches from unified git diffs.")
    evaluate_parser.add_argument("input_file",
                                 help="JSON file with Vul4J IDs and candidate git diffs.")
    evaluate_parser.add_argument("-o", "--output", type=str, default="evaluation_results.json",
                                 help="Output JSON file.")
    evaluate_parser.add_argument("-w", "--work-dir", type=str, default="/tmp/vul4j-evaluation",
                                 help="Working directory for checkouts.")
    evaluate_parser.add_argument("--output-dir", type=str,
                                 help="Directory for per-candidate artifacts.", required=False)
    evaluate_parser.add_argument("-i", "--id", nargs="+", type=str,
                                 help="Only evaluate the selected Vul4J IDs.", required=False)
    evaluate_parser.add_argument("--apply-only", action="store_true",
                                 help="Apply candidate diffs without compiling, testing, or running SpotBugs.")
    evaluate_parser.add_argument("--keep-checkouts", action="store_true",
                                 help="Keep checkout directories after evaluation.")
    evaluate_parser.set_defaults(func=vul4j_evaluate)

    options = parser.parse_args(args)

    if hasattr(options, 'func'):
        setup_logger(options.func.__name__.upper(), options.log, FILE_LOG_LEVEL)
        if getattr(options, "requires_config", True) and not utils.check_config():
            exit(1)
    else:
        parser.print_help()
        exit(1)

    options.func(options)
    exit(0)


if __name__ == "__main__":
    main()
