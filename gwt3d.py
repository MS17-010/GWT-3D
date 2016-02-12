#!/usr/bin/env python3
#  coding=utf-8


import argparse
import gwt3d.GWTRequest
import gwt3d.GWTEnumerator


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GWT-3D: GWT RPC pentest tool")
    parser.add_argument("--verbose", help="Verbose mode", action="store_true")
    parser.add_argument("--debug", help="Debug mode", action="store_true")

    subparsers = parser.add_subparsers(title="Actions", description="Possible actions",
                                       help="Actions that can be performed by the tool", dest="subparser_name")
    try:
        enum = subparsers.add_parser("enum", help="Enumerates all Java methods with their associated parameters",
                                    description="Possible options", aliases=['en', 'e'])
        decode = subparsers.add_parser("decode", help="Decodes a [set of] GWT RPC request(s)",
                                       description="Possible options", aliases=['de', 'dcd', 'dec', 'd'])
    except TypeError:
        enum = subparsers.add_parser("enum", help="Enumerates all Java methods with their associated parameters",
                                    description="Possible options")
        decode = subparsers.add_parser("decode", help="Decodes a [set of] GWT RPC request(s)",
                                       description="Possible options")

    enum.add_argument("-u", "--url", help="URL of the nocache.js file", required=True)
    enum.add_argument("-p", "--proxy", help="Proxy host and port (i.e.: \"http://localhost:8080\")")
    enum.add_argument("-b", "--basicauth", help="Basic authentication credentials", action="store_true")
    enum.add_argument("-c", "--cookies", help="Cookies to use to get the JS files")
    enum.add_argument("-o", "--output", default="stdout",
                        help="Absolute path were to store all parsed requests (default \"stdout\")", action="store")

    decode.add_argument("-i", "--input", help="The RPC request payload or Burp log file", action="store", required=True)
    decode.add_argument("-s", "--surround", help="Surrounds fuzzable parameters by a given string", action="store")
    decode.add_argument("-r", "--replace", help="Replaces fuzzable parameters by a given string", action="store")
    decode.add_argument("-b", "--burp", default=False,
                        help="Surrounds fuzzable parameters by Burp Intruder characters", action="store_true")
    decode.add_argument("-p", "--pretty", default=False,
                        help="Human readable formatting of the request", action="store_true")
    decode.add_argument("-o", "--output", default="stdout",
                        help="Absolute path were to store all parsed requests (default \"stdout\")", action="store")
    decode.add_argument("-m", "--methods",
                        help="You can specify a file were all Java methods are enumerated (line separated)."
                        "This file can be obtained by running the \"enum\" script", action="store")
    decode.add_argument("-f", "--fuzz",
                        help="Outputs only fuzzable strings", action="store_true")
    print()

    args = parser.parse_args()
    verbose = args.verbose
    debug = args.debug
    subparser_name = args.subparser_name

    if subparser_name in ['enum', 'en', 'e']:
        url = args.url
        output = args.output
        proxy = args.proxy
        basicauth = args.basicauth
        cookies = args.cookies

        gwt_enum = gwt3d.GWTEnumerator.GWTEnum(url, output, proxy, basicauth, cookies, verbose, debug)
        gwt_enum.enum()
        gwt_enum.display()
    elif subparser_name in ['decode', 'de', 'dcd', 'dec', 'd']:
        user_input = args.input
        burp = args.burp
        output = args.output
        fuzz = args.fuzz
        pretty = args.pretty
        replace = args.replace
        surround = args.surround
        methods = args.methods

        gwt_req_parser = gwt3d.GWTRequest.GWTReq(user_input, output, fuzz, pretty,
                                                 burp, replace, surround, methods, verbose, debug)
        gwt_req_parser.parse()
    else:
        parser.parse_args(["--help"])
