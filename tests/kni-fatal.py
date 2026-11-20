"""Check the original DPDK fatal behavior after each named KNI allocation fault."""
import argparse
import resource
import signal
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('app')
    parser.add_argument('profile', choices=('stats', 'slot'))
    args = parser.parse_args()

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    result = subprocess.run([args.app, 'fatal-' + args.profile], capture_output=True,
                            text=True, timeout=15)
    expected, marker = (
        (1, 'REAL_KNI_EXIT stats_null=1 failed=1 hotplug=0') if args.profile == 'stats'
        else (-signal.SIGABRT, 'REAL_KNI_PANIC slot_null=1 failed=1 hotplug=0')
    )
    if result.returncode != expected or result.stderr.count(marker) != 1:
        raise RuntimeError(f'KNI {args.profile} returned {result.returncode}:\n'
                           + result.stdout + result.stderr)
    print(marker)


if __name__ == '__main__':
    main()
