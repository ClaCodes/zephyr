# vim: set syntax=python ts=4 :
#
# Copyright (c) 2022 Google
# SPDX-License-Identifier: Apache-2.0

import argparse
import logging
import os
import shutil
import sys
import time

import colorama
from colorama import Fore
from twisterlib.coverage import run_coverage
from twisterlib.environment import TwisterEnv
from twisterlib.hardwaremap import HardwareMap
from twisterlib.log_helper import close_logging, setup_logging
from twisterlib.package import Artifacts
from twisterlib.reports import Reporting
from twisterlib.runner import TwisterRunner
from twisterlib.statuses import TwisterStatus
from twisterlib.testplan import TestPlan


def init_color(colorama_strip):
    colorama.init(strip=colorama_strip)


def twister(options: argparse.Namespace, default_options: argparse.Namespace):
    start_time = time.time()

    # Configure color output
    color_strip = False if options.force_color else None

    colorama.init(strip=color_strip)
    init_color(colorama_strip=color_strip)

    previous_results = None
    # Cleanup
    if (
        options.no_clean
        or options.only_failed
        or options.test_only
        or options.report_summary is not None
    ):
        if os.path.exists(options.outdir):
            print("Keeping artifacts untouched")
    elif options.last_metrics:
        ls = os.path.join(options.outdir, "twister.json")
        if os.path.exists(ls):
            with open(ls) as fp:
                previous_results = fp.read()
        else:
            sys.exit(f"Can't compare metrics with non existing file {ls}")
    elif os.path.exists(options.outdir):
        if options.clobber_output:
            print(f"Deleting output directory {options.outdir}")
            shutil.rmtree(options.outdir)
        else:
            for i in range(1, 100):
                new_out = options.outdir + f".{i}"
                if not os.path.exists(new_out):
                    print(f"Renaming previous output directory to {new_out}")
                    shutil.move(options.outdir, new_out)
                    break
            else:
                sys.exit(f"Too many '{options.outdir}.*' directories. Run either with --no-clean, "
                         "or --clobber-output, or delete these directories manually.")

    previous_results_file = None
    os.makedirs(options.outdir, exist_ok=True)
    if options.last_metrics and previous_results:
        previous_results_file = os.path.join(options.outdir, "baseline.json")
        with open(previous_results_file, "w") as fp:
            fp.write(previous_results)

    setup_logging(options.outdir, options.log_file, options.log_level, options.timestamps)
    logger = logging.getLogger("twister")

    env = TwisterEnv(options, default_options)
    env.discover()

    hwm = HardwareMap(env)
    ret = hwm.discover()
    if ret == 0:
        return 0

    env.hwm = hwm

    tplan = TestPlan(env)
    try:
        tplan.discover()
    except RuntimeError as e:
        logger.error(f"{e}")
        return 1

    if tplan.report() == 0:
        return 0

    try:
        tplan.load()
    except RuntimeError as e:
        logger.error(f"{e}")
        return 1

    # if we are using command line platform filter, no need to list every
    # other platform as excluded, we know that already.
    # Show only the discards that apply to the selected platforms on the
    # command line

    if options.verbose > 0:
        for i in tplan.instances.values():
            if i.status in [TwisterStatus.SKIP,TwisterStatus.FILTER]:
                if options.platform and not tplan.check_platform(i.platform, options.platform):
                    continue
                # Filtered tests should be visable only when verbosity > 1
                if options.verbose < 2 and i.status == TwisterStatus.FILTER:
                    continue
                res = i.reason
                if "Quarantine" in i.reason:
                    res = "Quarantined"
                logger.info(
                    f"{i.platform.name:<25} {i.testsuite.name:<50}"
                    f" {Fore.YELLOW}{i.status.upper()}{Fore.RESET}: {res}"
                    )

    report = Reporting(tplan, env)
    plan_file = os.path.join(options.outdir, "testplan.json")
    if not os.path.exists(plan_file):
        report.json_report(plan_file, env.version)

    if options.save_tests:
        report.json_report(options.save_tests, env.version)
        return 0

    if options.report_summary is not None:
        if options.report_summary < 0:
            logger.error("The report summary value cannot be less than 0")
            return 1
        report.synopsis()
        return 0

    # FIXME: This is a workaround for the fact that the hardware map can be usng
    # the short name of the platform, while the testplan is using the full name.
    #
    # convert platform names coming from the hardware map to the full target
    # name.
    # this is needed to match the platform names in the testplan.
    for d in hwm.duts:
        if d.platform in tplan.platform_names:
            d.platform = tplan.get_platform(d.platform).name

    if options.device_testing and not options.build_only:
        print("\nDevice testing on:")
        hwm.dump(filtered=tplan.selected_platforms)
        print("")

    if options.dry_run:
        duration = time.time() - start_time
        logger.info(f"Completed in {duration} seconds")
        return 0

    if options.short_build_path:
        tplan.create_build_dir_links()

    runner = TwisterRunner(tplan.instances, tplan.testsuites, env)
    runner.duts = hwm.duts
    runner.run()

    # figure out which report to use for size comparison
    report_to_use = None
    if options.compare_report:
        report_to_use = options.compare_report
    elif options.last_metrics:
        report_to_use = previous_results_file

    report.footprint_reports(
        report_to_use,
        options.show_footprint,
        options.all_deltas,
        options.footprint_threshold,
        options.last_metrics,
    )

    duration = time.time() - start_time

    if options.verbose > 1:
        runner.results.summary()

    report.summary(runner.results, duration)

    report.coverage_status = True
    if options.coverage and not options.disable_coverage_aggregation:
        if not options.build_only:
            report.coverage_status, report.coverage = run_coverage(options, tplan)
        else:
            logger.info("Skipping coverage report generation due to --build-only.")

    if options.device_testing and not options.build_only:
        hwm.summary(tplan.selected_platforms)

    report.save_reports(
        options.report_name,
        options.report_suffix,
        options.report_dir,
        options.no_update,
        options.platform_reports,
    )

    report.synopsis()

    if options.package_artifacts:
        artifacts = Artifacts(env)
        artifacts.package()

    if (
        runner.results.failed
        or runner.results.error
        or (tplan.warnings and options.warnings_as_errors)
        or (options.coverage and not report.coverage_status)
    ):
        if env.options.quit_on_failure:
            logger.info("twister aborted because of a failure/error")
        else:
            logger.info("Run completed")
        return 1

    logger.info("Run completed")
    return 0


def main(options: argparse.Namespace, default_options: argparse.Namespace):
    try:
        return_code = twister(options, default_options)
    finally:
        close_logging()
    return return_code
