#!/usr/bin/python3
import pexpect
from time import sleep
from datetime import datetime
import subprocess

telnet_console = "10.38.131.6"
atf_port = "7015"
scp_port = "7014"

atf_child = pexpect.spawn("telnet {} {}".format(telnet_console, atf_port))
scp_child = pexpect.spawn("telnet {} {}".format(telnet_console, scp_port))


def linux_cmd(cmd, is_error=False):
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True
    )
    full_output = proc.stdout.decode("utf-8", 'replace')
    full_error = ''
    if proc.stderr is not None:
        full_error = proc.stderr.decode("utf-8", 'replace')
    else:
        full_error = ""

    if proc.returncode and not is_error:
        error=f"return code {proc.returncode} data {full_output} {full_error}"
        raise Exception(error)
    return proc.returncode, "%s %s" % (full_output, full_error)

def Set_Up_ATF_Boot_Failure_Normal_Config(): 
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power off".format(bmc_ip))
    cmd="gpiotool --set-data-low 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -s 0x1 -o 0x1101F0"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="gpiotool --set-data-high 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    sleep(60)
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power on".format(bmc_ip))

def Set_Up_ATF_Boot_Failure_Normal_Config_Last_Know(): 
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power off".format(bmc_ip))
    cmd="gpiotool --set-data-low 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -s 0x1 -o 0x1101F0"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -s 0x1 -o 0x1001F0"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="gpiotool --set-data-high 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    sleep(60)
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power on".format(bmc_ip))

def Set_Up_UEFI_Boot_Failure_Normal_Config():
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power off".format(bmc_ip))
    cmd="gpiotool --set-data-low 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -s 0x1 -o 0x1101F8"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="gpiotool --set-data-high 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    sleep(60)
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power on".format(bmc_ip))


def Set_Up_UEFI_Boot_Failure_Normal_Config_Last_Know(): 
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power off".format(bmc_ip))
    cmd="gpiotool --set-data-low 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -s 0x1 -o 0x1101F8"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -s 0x1 -o 0x1001F8"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="gpiotool --set-data-high 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    sleep(60)
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power on".format(bmc_ip))


def Set_Up_PMpro_Boot_Failure_Normal_Config():
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power off".format(bmc_ip))
    cmd="gpiotool --set-data-low 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -s 0x1 -o 0x114068"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="gpiotool --set-data-high 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    sleep(60)
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power on".format(bmc_ip))
    

def Set_Up_UEFI_Boot_Failure_Normal_Config_Last_Know(): 
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power off".format(bmc_ip))
    cmd="gpiotool --set-data-low 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -s 0x1 -o 0x114068"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -s 0x1 -o 0x104068"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="gpiotool --set-data-high 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    sleep(60)
    linux_cmd("ipmitool -H {} -U ADMIN -P ADMIN -I lanplus chassis power on".format(bmc_ip))
    
 
def Clear_NVparam():
    cmd="gpiotool --set-data-low 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -c -o 0x110000"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="nvparm -c -o 0x100000"
    Remote_Obj.bmc_ssh_cmd(cmd)
    cmd="gpiotool --set-data-high 226"
    Remote_Obj.bmc_ssh_cmd(cmd)
 

def Check_ATF_Failsafe():
    Set_Up_ATF_Boot_Failure_Normal_Config()
    scp_child.expect("BL31: Image v.+", timeout=60)
    start = time.time()
    scp_child.expect("NS Watchdog expired.+", timeout=1800)
    end = time.time()
    hours, rem = divmod(end-start, 3600)
    minutes, seconds = divmod(rem, 60)
    print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
    
    sleep(300)
    Clear_NVparam()
    Set_Up_ATF_Boot_Failure_Normal_Config_Last_Know()
    for i in range(3):
        print ("start at index {i} ")
        scp_child.expect("BL31: Image v.+", timeout=60)
        start = time.time()
        scp_child.expect("NS Watchdog expired.+", timeout=1800)
        end = time.time()
        hours, rem = divmod(end-start, 3600)
        minutes, seconds = divmod(rem, 60)
        print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
    Clear_NVparam()
def Check_UEFI_Failsafe():    
    Set_Up_ATF_Boot_Failure_Normal_Config()
    atf_child.expect("BL31: Image v.+", timeout=60)
    start = time.time()
    atf_child.expect("NS Watchdog expired.+", timeout=1800)
    end = time.time()
    hours, rem = divmod(end-start, 3600)
    minutes, seconds = divmod(rem, 60)
    print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
    
    sleep(300)
    Clear_NVparam()
    Set_Up_ATF_Boot_Failure_Normal_Config_Last_Know()
    for i in range(3):
        print ("start at index {i} ")
        atf_child.expect("BL31: Image v.+", timeout=60)
        start = time.time()
        atf_child.expect("NS Watchdog expired.+", timeout=1800)
        end = time.time()
        hours, rem = divmod(end-start, 3600)
        minutes, seconds = divmod(rem, 60)
        print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
    Clear_NVparam()
def Check_Pmpro_Failsafe():
    Set_Up_ATF_Boot_Failure_Normal_Config()
    scp_child.expect("BL31: Image v.+", timeout=60)
    start = time.time()
    scp_child.expect("NS Watchdog expired.+", timeout=1800)
    end = time.time()
    hours, rem = divmod(end-start, 3600)
    minutes, seconds = divmod(rem, 60)
    print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
    
    sleep(300)
    Clear_NVparam()
    Set_Up_ATF_Boot_Failure_Normal_Config_Last_Know()
    for i in range(3):
        print ("start at index {i} ")
        scp_child.expect("BL31: Image v.+", timeout=60)
        start = time.time()
        scp_child.expect("NS Watchdog expired.+", timeout=1800)
        end = time.time()
        hours, rem = divmod(end-start, 3600)
        minutes, seconds = divmod(rem, 60)
        print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
    Clear_NVparam()   
