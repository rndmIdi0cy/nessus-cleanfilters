#!/usr/bin/env python

import requests
import argparse
import sys
import os

####################################################################
# Requirements:
#   pip3 install requests
#
# About:
#   This python script will create show and/or delete filters for a
#   user account or multiple accounts.
#
# Help:
#  usage: clean-filters.py [-h] [-target TARGET] [-targetlist TARGETLIST] [-sharedby SHAREDBY] [-whatif]
#
#  Delete Vulnerability filters for a user account
#
#  optional arguments:
#    -h, --help            show this help message and exit
#    -target TARGET        Username to target
#    -targetlist TARGETLIST
#                          Path to text file containing list of usernames
#    -sharedby SHAREDBY    Filter saved searches 'shared by' username
#    -whatif               Run but do not delete
#
#   Examples:
#       Delete filters that are shared by admin@domain.com with the user@domain.com account 
#       ./clean-filters.py -target user@domain.com -sharedby admin@domain.com
#
#       List filters that would be deleted for user@domain.com
#       ./clean-filters.py -target user@domain.com -whatif
#

#####################################################################
# Tenable.IO API Configuration
BASE_URL = "https://cloud.tenable.com"
ACCESS_KEY = "_PUT_YOUR_ACCESS_KEY_HERE_"
SECRET_KEY = "_PUT_YOUR_SECRET_KEY_HERE_"
#####################################################################

#####################################################################
# Requests headers
HEADERS = {
    "accept": "application/json",
    "X-ApiKeys": "accessKey={}; secretKey={}".format(ACCESS_KEY, SECRET_KEY),
    "User-Agent": "TIOApi/1.0 Python/{0:d}.{1:d}.{2:d}".format(sys.version_info[0],
                                                               sys.version_info[1],
                                                               sys.version_info[2])
}
#####################################################################


def print_success(msg):
    if os.name == "nt":
        print("[+] {}".format(msg))
    else:
        print("\033[1;32m[+] \033[1;m{}".format(msg))


def print_status(msg):
    if os.name == "nt":
        print("[*] {}".format(msg))
    else:
        print("\033[1;34m[*] \033[1;m{}".format(msg))


def print_failure(msg):
    if os.name == "nt":
        print("[-] {}".format(msg))
    else:
        print("\033[1;31m[-] \033[1;m{}".format(msg))


def print_error(msg):
    if os.name == "nt":
        print("[!] {}".format(msg))
    else:
        print("\033[1;33m[!] \033[1;m{}".format(msg))


def get_tio_data(uri, username):
    HEADERS.update({
        "X-Impersonate": "username={}".format(username)
    })

    try:
        response = requests.get("{0}/{1}".format(BASE_URL, uri),
                                headers=HEADERS)

        if response.status_code == 403:
            print_error("Forbidden error, check username again or if you have "
                        "appropriate permissions")
            sys.exit(1)

        if response.status_code != 200:
            print_error("Tenable IO: {}".format(response.json()["error"]))
            sys.exit(1)

        return response.json()
    except Exception as e:
        print_error("failed : {}".format(str(e)))
        sys.exit(1)


def get_filter_list(filters, shared_by_user=None):
    filter_list = {}
    filter_list["info"] = []
    for search in filters["saved_searches"]:
        filter_uuid = search["uuid"]
        filter_name = search["name"]

        if shared_by_user is None:
            data = {
                "filter_uuid": filter_uuid,
                "filter_name": filter_name
            }
        else:
            if "shared_by" in search and search["shared_by"] == shared_by_user:
                data = {
                    "filter_uuid": filter_uuid,
                    "filter_name": filter_name
                }

        filter_list["info"].append(data)

    return filter_list


def delete_filter(filter_uuid, filter_name, username):
    HEADERS.update({
        "X-Impersonate": "username={}".format(username)
    })

    try:
        response = requests.delete("{0}/saved-search/{1}".format(BASE_URL, filter_uuid),
                                   headers=HEADERS)

        if response.status_code != 204:
            print_error("Tenable IO: {}".format(response.json()["error"]))
            sys.exit(1)

        print_status("successfully deleted {}".format(filter_name))
    except Exception as e:
        print_error("failed : {}".format(str(e)))
        sys.exit(1)


def run(target, whatif=False, shared_by_user=None):
    print_success("getting saved searches for {}".format(target))
    filters = get_tio_data("saved-search?view=VulnerabilitiesWorkbench", target)

    print_status("{} total filters".format(len(filters["saved_searches"])))
    print_success("parsing saved searches")
    filterList = get_filter_list(filters, shared_by_user)

    print_status("{} set for deletion".format(len(filterList["info"])))

    if len(filterList["info"]) > 0:
        if whatif:
            print_success("running with 'whatif'; listing filters that would be deleted")
        else:
            print_success("deleting filters")

        for qfilter in filterList["info"]:
            if whatif:
                print_status("{0} : {1}".format(qfilter["filter_uuid"], qfilter["filter_name"]))
            else:
                delete_filter(qfilter["filter_uuid"], qfilter["filter_name"], target)
    else:
        print_status("no applicable filters found for user {}".format(target))


def main():
    parser = argparse.ArgumentParser(add_help=True,
                                     description="Delete Vulnerability filters for a user account")
    parser.add_argument("-target", type=str,
                        help="Username to target")
    parser.add_argument("-targetlist", type=str,
                        help="Path to text file containing list of usernames")
    parser.add_argument("-sharedby", type=str,
                        default=None,
                        help="Filter saved searches 'shared by' username")
    parser.add_argument("-whatif", action="store_true",
                        help="Run but do not delete")
    options = parser.parse_args()

    if (ACCESS_KEY == '_PUT_YOUR_ACCESS_KEY_HERE_') or (SECRET_KEY == '_PUT_YOUR_SECRET_KEY_HERE_'):
        print_error('Please get your API key from Tenable.IO and replace ACCESS_KEY and SECRET_KEY')
        exit(1)

    if options.target is None and options.targetlist is None:
        print_error("missing a target(s)")
        parser.print_help()
        sys.exit(1)

    if options.target and options.targetlist:
        print_error("target and targetlist cannot be used together")
        parser.print_help()
        sys.exit(1)

    if options.targetlist:
        if not os.path.exists(options.targetlist):
            print_error("could not find target file at {}".format(options.targetlist))
            parser.print_help()
            sys.exit(1)

        tlist = open(options.targetlist, "r")
        with open(options.targetlist, "r") as tlist:
            for target in tlist:
                target = target.strip()
                run(target, options.whatif, options.sharedby)
    else:
        run(options.target, options.whatif, options.sharedby)


if __name__ == "__main__":
    main()
