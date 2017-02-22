#!/usr/bin/env python
# -*- coding: utf-8 -*-
#TODO refactoring for python3

from pymisp import PyMISP
from keys import misp_url, misp_key
import sys
import pprint
import argparse
import subprocess
import json

# For python2 & 3 compat, a bit dirty, but it seems to be the least bad one
try:
    input = raw_input
except NameError:
    pass


def init(url, key):
    return PyMISP(url, key, True, 'json')

if __name__ == '__main__':
        misp = init(misp_url, misp_key)
        parser = argparse.ArgumentParser(description='TEST')
        parser.add_argument("-r", "--read", required=True,
                                                help="pcap/dumpcap file that should be read by tshark ")
        parser.add_argument("-f","--filter", required=False,
                                                help="Prefix that should be skipped (substring)")
        parser.add_argument("-s","--source", help = "Describe the source of the pcap",
                                                required=False, default="undefined")
        parser.add_argument("-t","--type", required=False,
                                                help="Specify the type of sightings: 0=Default,1=False positive", default=0)
        parser.add_argument("-v","--verbose", default=False, action='store_true')
        args = parser.parse_args()

        p = subprocess.Popen(["tshark","-n","-r", args.read,
                                      "-Tfields", "-eframe.time_epoch",
                                  "-Tfields", "-eip.src",
                                          "-Tfields", "-eip.dst"],
                                          stdout=subprocess.PIPE, shell=False)

#FIXME Create multiple json docs when large pcaps are used.
for line in p.stdout:
        try:
                line = line.rstrip()
                if isinstance(line, bytes):
                        line=line.decode('ascii')

                #Handle nested dissected nested protocols
                line = line.replace(',',' ')
                t = line.split()
                ts = t[0].split('.')[0]
                for ip in t[1:]:
                        doc = {}
                        if args.filter is not None and ip.startswith(args.filter[0]):
                                continue
                        doc["values"] = [ip]
                        doc["source"] = args.source
                        doc["type"] = args.type
                        doc["timestamp"] = str(ts)
                        jdoc = json.dumps(doc)
                        if args.verbose:
                                print ("Input JSON to MISP: {}".format(jdoc))
                        res = misp.set_sightings(jdoc)
                        if args.verbose:
                                print ("MISP response: {}".format(res))
        except IndexError as e:
                print(e)

