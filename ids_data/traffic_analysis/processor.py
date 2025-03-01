import os
import ctypes
import subprocess


def exec_cmd(cmd, wait=False):
    p = subprocess.Popen(cmd, shell=True)
    if wait:
        p.wait()

class raw_processor():

    def process(self, input_folder, output_folder):
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        # single file
        if os.path.isfile(input_folder):

            print('input_f', input_folder)
            fsize = os.path.getsize(input_folder)
            print('size:', fsize)
            self.pcap2csv(input_folder, output_folder)
        # TODO: support multiple files
        else:
            files = os.listdir(input_folder)
            files = list(filter(lambda f: f.endswith(".pcap") or f.startswith("cap") or f.startswith("UCAP"), files))
            #print('files: ', files)
            for input_f in files:
                input_f = input_folder + input_f
                if not (input_f.endswith(".pcap")):
                    input_f_old = input_f.replace(' ', '\ ')
                    input_f_new = ''.join(input_f.split(' '))
                    exec_cmd("mv " + input_f_old + ' ' + input_f_new + '.pcap', wait=True)
                    input_f = input_f_new + '.pcap'
                print('input_f', input_f)
                fsize = os.path.getsize(input_f)
                print('size:', fsize)
                self.pcap2csv(input_f, output_folder)
                """
                if fsize >= 1000000000: #
                    exec_cmd("editcap -c 2000000 "+input_f+' '+ input_f, wait=True)
                    newfiles = os.listdir(input_folder)
                    ori_name = input_f.split('/')[-1]
                    print('name', ori_name[:-5])
                    newfiles = list(filter(lambda f: ori_name[:-5] in f, newfiles))
                    for f in newfiles:
                        if f != ori_name:
                            self.pcap2csv(input_folder + f, output_folder)
                else:
                    self.pcap2csv(input_f, output_folder)
                #"""
        # compile shared library for converting pcap to csv

    def pcap2csv(self, input_folder, output_folder):
        csv_file = os.path.join(
            output_folder,
            os.path.splitext(os.path.basename(input_folder))[0] + "_out.csv")
        if not os.path.exists(csv_file):
            cwd = os.path.dirname(os.path.abspath(__file__))
            cmd = f"cd {cwd} && \
                                cc -fPIC -shared -o pcap2csv.so main.c -lm -lpcap"
            exec_cmd(cmd, wait=True)

            pcap2csv_func = ctypes.CDLL(
                os.path.join(cwd, "pcap2csv.so")).pcap2csv
            pcap2csv_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

            pcap2csv_func(
                input_folder.encode('utf-8'),  # pcap file
                csv_file.encode('utf-8')  # csv file
            )
            print(f"{input_folder} has been converted to {csv_file}")
        else:
            print(csv_file+' exist')

if __name__ == "__main__":
    proc = raw_processor()
    data = 'unsw'
    if data == 'cic17':
        root_path = '/mnt/ff1f01b3-85e2-407c-8f5d-cdcee532daa5/cic17/ori_pcap/'
        proc.process(root_path, root_path + '/proc_pcap2csv/')
    else:
        if data == 'unsw':
            root_path = '/mnt/ff1f01b3-85e2-407c-8f5d-cdcee532daa5/UNSW15/UNSW-NB15-pcap-files/'
        if data == 'cic18':
            root_path = '/mnt/ff1f01b3-85e2-407c-8f5d-cdcee532daa5/cse-cic-ids2018/original_traffic/'
        paths = os.listdir(root_path)

        files = list(filter(lambda f: os.path.isdir(root_path+f), paths))
        print(files)
        for path in files:
            if data == 'unsw':
                print(root_path+path+'/', root_path+path+'/proc_pcap2csv/')
                proc.process(root_path+path+'/', root_path+path+'/proc_pcap2csv/')
            if data == 'cic18':
                print(root_path+path+'/pcap/', root_path+path+'/proc_pcap2csv/')
                proc.process(root_path+path+'/pcap/', root_path+path+'/proc_pcap2csv/')

# ls -Rl | awk '{if($7==1) print$9}'