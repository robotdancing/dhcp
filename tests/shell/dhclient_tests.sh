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

    # Start Control Agent.
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

version_test  "dhclient.version"
shutdown_test "dhclient.sigterm" 15
