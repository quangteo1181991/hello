#!/usr/bin/python

# open bug only support 1 sha 
# open 1 bug for server 
# run 100 cycles 


import hashlib 
import argparse
import sys
import pprint
import logging
import subprocess
import json


logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',level=logging.DEBUG)
VERSION='1.0.0'
logger = logging.getLogger(__name__)

class TPM:
    def __init__(self,file):
        self.path_ibm_utils='/root/quang/tpm/ibmtpm20tss-tss/utils/'
        self.metadata={}
        self.logger = logging.getLogger("TPM")
        self.logger.setLevel(logging.DEBUG)
        self.file_name=file
        self.create_file()
    
    def create_file(self):
        self.logger.info(f"################# create file {self.file_name} ##########################")
        f = open(self.file_name, "w+")
        f.close()
    def write_log(self, msg, mode='a+'):
        try:
            f = open(self.file_name, mode)
            f.write(msg)
            f.close()
            return 1
        except Exception as e:
            self.logger.error('Can not write data to file ')
            
    def remove_file(self):
        try:
            os.system("rm -rf %s" % self.debug_file)
        except Exception as e:
            pass
            
    def linux_cmd(self, cmd,allow_fail=False):
        debug_data=f"running cmd command {cmd}"
        self.write_log(debug_data)
        self.write_log('\n')
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True
        )
        full_output = proc.stdout.decode("utf-8", 'replace')
        self.write_log(full_output)
        if not allow_fail and proc.returncode:
            raise Exception('command is failed')
        return full_output
    def gen_metadata(self):
        tmp={}
        for index in range(0,24):
            pcr_inex= hex(index)
            #tmp={"sha1":[], "sha256":[]}
            pcr_res = "pcr_%d"%index
            read_data=self.read_sha1_pcr_register(pcr_inex.replace('0x',''))
            tmp["sha1"]=read_data.splitlines()
            #read_data=self.read_sha256_pcr_register(pcr_inex.replace('0x',''))
            #tmp["sha256"]=read_data.splitlines()
            self.metadata[pcr_res]=tmp
        pprint.pprint(self.metadata)
        return self.metadata
    def read_sha1_pcr_register(self,index):
        #cmd =self.path_ibm_utils +"pcrread -halg sha1 -ha %d"%index
        cmd =f"eltt2 -r {index}"
        data=self.linux_cmd(cmd)
        return data
        
    def read_sha256_pcr_register(self,index):
        #cmd =self.path_ibm_utils +"pcrread -halg sha256 -ha %d"%index
        cmd =f"eltt2 -R {index}"
        data=self.linux_cmd(cmd)
        return data
        
    def read_sha1_pcr_registers(self):
        for index in range(0,24):
            #cmd =self.path_ibm_utils +"pcrread -halg sha1 -ha %d"%index
            cmd =f"eltt2 -r {index}"
            data=self.linux_cmd(cmd)
            self.logger.debug(f"sha1:  {data}")
    
    def read_sha256_pcr_registers(self):
        for index in range(0,24):
            #cmd =self.path_ibm_utils +"pcrread -halg sha256 -ha %d"%index
            cmd =f"eltt2 -R {index}"
            data=self.linux_cmd(cmd)
            self.logger.debug(f"sha256:  {data}")

    def gen_sha_256(data): 
        if isinstance (data,str):
            result = hashlib.sha256(data.encode()) 
            print("The hexadecimal equivalent of SHA256 is : ") 
            print(result.hexdigest()) 
            print ("\r") 
        else:
            pass
    
    def gen_sha_1(data): 
        if isinstance (data,str):
            result = hashlib.sha1(data.encode()) 
            print("The hexadecimal equivalent of SHA1 is : ") 
            print(result.hexdigest()) 
            print ("\r") 
        else:
            pass
            
def main():
    parser = argparse.ArgumentParser(description='check TPM')
    parser.add_argument('--sha1', help='read SHA1 data',type=str, default='')
    parser.add_argument('--sha256', help='read SHA256 data',type=str, default='')
    parser.add_argument('--register', help='select register to read',type=str,default='')
    parser.add_argument('--file', help='select register to read',type=str,default='debug_tpm.txt',required=True )
    args = vars(parser.parse_args())
    sha1=args['sha1']
    sha256=args['sha256']
    file=args['file']
    tpm=TPM(file)
    tpm.gen_metadata()
if  __name__ == '__main__':
    main()
