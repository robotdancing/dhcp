# Copyright (C) 2016-2017 Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

EXPECTED_VERSION="isc-dhclient-4.4.0-dev"

# dhclient configuration. Currently empty, but future tests may use it.
CONFIG="#nothing"

CFG_FILE=/home/thomson/devel/dhcp-git/tests/dhclient.conf

# Temporary log file. Make sure this location is writeable.
LOG_FILE=/home/thomson/devel/dhcp-git/tests/dhclient.log

LEASE_FILE=/home/thomson/devel/dhcp-git/tests/dhclient.leases

PID_FILE=/home/thomson/devel/dhcp-git/tests/dhclient.pid

SCRIPT_FILE=/home/thomson/devel/dhcp-git/tests/shell/echo.sh

SCRIPT_LOG_FILE=/home/thomson/devel/dhcp-git/tests/echo.log

IFACE=lo

bin="dhclient"
bin_path=/home/thomson/devel/dhcp-git/client

# Import common test library.
. /home/thomson/devel/dhcp-git/tests/shell/dhcp_test_lib.sh

# This test verifies that dhclient shuts down gracefully when it
# receives a SIGINT or SIGTERM signal.
shutdown_test() {
    test_name=${1}  # Test name
    signum=${2}     # Signal number
    # Log the start of the test and print test name.
    test_start ${test_name}

    if [ "$EUID" -ne 0 ]; then
        printf "This test requires to be run as root, skipping.\n"
        test_finish 2
        return
    fi

    # Remove dangling instances and remove log files.
    cleanup

    # Create new configuration file.
    create_config "${CONFIG}"

    # Start a client.
    start_kea ${bin_path}/${bin}
    # Wait up to 5s for Control Agent to start.
    wait_for_kea 5
    if [ ${_WAIT_FOR_KEA} -eq 0 ]; then
        printf "ERROR: timeout waiting for dhclient to start.\n"
        clean_exit 1
    fi

    # Check if it is still running. It could have terminated (e.g. as a result
    # of configuration failure).
    get_pid ${bin}
    if [ ${_GET_PIDS_NUM} -ne 1 ]; then
        printf "ERROR: expected one dhclient process to be started. Found %d processes\
 started.\n" ${_GET_PIDS_NUM}
        clean_exit 1
    fi

    # Check in the log file, how many times server has been configured.
    # It should be just once on startup.
    check_client_started
    if [ ${_CHECK_CLIENT_STARTED} -ne 1 ]; then
        printf "ERROR: client start failed.\n"
        clean_exit 1
    else
        printf "dhclient started successfully.\n"
    fi

    # Send signal to Control Agent (SIGTERM, SIGINT etc.)
    send_signal ${signum} ${bin}

    # Make sure the server is down.
    wait_for_process_down 5 ${bin}
    assert_eq 1 ${_WAIT_FOR_PROCESS_DOWN} \
        "Expected wait_for_server_down return %d, returned %d"

    test_finish 0
}

# This test verifies that dhclient actually calls a shell script.
# The first reason to call is PREINIT. It's called before any
# actual DHCP operations are conducted.
script_call_preinit_test() {
    test_name="dhclient.script-call.preinit" # Test name
    grep_expr="reason=PREINIT"  # name of the expression the script should log.

    # Log the start of the test and print test name.
    test_start ${test_name}

    # Currently we need root to start a client, hence this check.
    if [ "$EUID" -ne 0 ]; then
        printf "This test requires to be run as root, skipping.\n"
        test_finish 2
        return
    fi

    # Remove dangling instances and remove log files.
    cleanup

    # Create new configuration file.
    create_config "${CONFIG}"

    # Start Control Agent.
    start_kea ${bin_path}/${bin} -1 ${IFACE}
    # Wait up to 120 for dhclient to fail (there's no server running).
    wait_for_kea 5

    # Check that the script was called and it reported appropriate
    # reason.
    grep_file ${SCRIPT_LOG_FILE} ${grep_expr} 1

    # Send SIGTERM signal if the process is still running
    send_signal 15 ${bin}

    # Make sure the server is down.
    wait_for_process_down 5 ${bin}
    assert_eq 1 ${_WAIT_FOR_PROCESS_DOWN} \
        "Expected wait_for_server_down return %d, returned %d"

    test_finish 0
}

# This test verifies that dhclient actually calls a shell script.
script_call_1fail_test() {
    test_name="dhclient.script-call.onetry-fail" # Test name
    grep_expr="reason=FAIL"  # name of the expression the script should log.
    timeout=120

    # Log the start of the test and print test name.
    test_start ${test_name}

    # Currently we need root to start a client, hence this check.
    if [ "$EUID" -ne 0 ]; then
        printf "This test requires to be run as root, skipping.\n"
        test_finish 2
        return
    fi

    printf "This test may take up to ${timeout} seconds to run. Sorry"

    # Remove dangling instances and remove log files.
    cleanup

    # Create new configuration file.
    create_config "${CONFIG}"

    # Start Control Agent.
    start_kea ${bin_path}/${bin} -1 ${IFACE}
    # Wait up to 120s for dhclient to fail (there's no server running).
    wait_for_message ${timeout} "Unable to obtain a lease on first try.  Exiting." 1

    # Check that the script was called and it reported appropriate
    # reason.
    grep_file ${SCRIPT_LOG_FILE} ${grep_expr} 1

    # Send SIGTERM signal if the process is still running
    get_pid ${proc_name}
    if [ ${_GET_PIDS_NUM} -eq 1 ]; then
        # Assuming the client worked as expected, the process should be long
        # gone. However, if it misbehaved for whatever reason, we will send
        # a SIGKILL and wait a second. This should kill that bastard.
        send_signal 9 ${bin}
        sleep 1
    fi


    test_finish 0
}

version_test  "dhclient.version"
script_call_preinit_test
script_call_1fail_test
