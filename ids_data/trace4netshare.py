import os
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

info_dict = {
    'cic17': {
        'normal': ['normal_normal.csv'],
        #'slow_dos': ['DoS_DoS-SlowHTTPTest.csv', 'DoS_DoS-Slowloris.csv'],
        #'bruteforce': ['bruteforce_SSH-BruteForce.csv', 'bruteforce_FTP-BruteForce.csv'],
        'portscan': ['infiltration_nmapportscan.csv'],
        #'web_attack': ['webattack_BruteForce-XSS.csv', 'webattack_BruteForce-Web.csv',
        #               'webattack_SQL-Injection.csv']
    },
    'cic18': {
        'normal': ['normal_normal.csv'],
        'slow_dos': ['DoS_DoS-SlowHTTPTest.csv', 'DoS_DoS-Slowloris.csv'],
        'bruteforce': ['bruteforce_SSH-BruteForce.csv', 'bruteforce_FTP-BruteForce.csv'],
    },
    'unsw': {
        'normal': ['normal.csv'],
        #'backdoor': ['Backdoor.csv', 'Backdoors.csv'],
        #'reconnaissance': ['Reconnaissance.csv'],
        'fuzzer': ['Fuzzers.csv'],
        #'generic': ['Generic.csv'],
        'exploits': ['Exploits.csv']
    }
}


def prepare_csv(data_name, cls, data_list, num=6000):
    raw_path = '/mnt/ff1f01b3-85e2-407c-8f5d-cdcee532daa5/NIDS_CLIP/'
    out_list = []

    for i, name in enumerate(data_list):

        df = pd.read_csv(raw_path + data_name + '/data_csv/' + name, encoding='unicode_escape')
        if data_name == 'unsw':
            df.columns = ['Unnamed: 0','index','srcip','dstip','srcport','dstport','proto','time','pkt_len','version',
                          'ihl','phl','tos','id','flag','off','ttl','chksum','tcp_flag','windows','pl_len','payload']
            df['ihl'] = df['ihl'] * 4
            df['phl'] = df['phl'] * 4
            df.insert(6, 'direc', 0)
            df = df.apply(unif5tuple_adddirec, axis=1)
        df = df.sort_values(by=['index', 'time'], ascending=(True, True))

        index_list = list(set(df['index']))
        num_save = 0
        for n, idx in enumerate(index_list):
            tmp = df[df['index'] == idx]

            tmp['head_len'] = tmp['ihl'] + tmp['phl']

            tmp = tmp.filter(items=['index', 'srcip', 'dstip', 'srcport', 'dstport', 'proto',
                                   'direc', 'time', 'pkt_len', 'head_len', 'tcp_flag', 'windows'])
            tmp['tcp_flag'] = tmp['tcp_flag'].apply(flag_int2str)
            tmp['index'] = num_save + i * (num // len(data_list))
            #tmp['time'] = tmp['time'] - tmp['time'].min()
            if len(tmp) < 1000:
                num_save = num_save + 1
                tmp.to_csv('./'+data_name+'_'+cls_name+'_raw_long.csv', mode='a', header=False, index=None) #_longtime
                print('save', './'+data_name+'_'+cls_name+'_raw_long.csv', num_save, ' in ', num // len(data_list)) #_longtime
            if num_save == (num // len(data_list)):
                break


def flag_int2str(flag):
    flag_str = format(flag, '#010b')[-8:]
    tcp_flag = 'CEUAPRSF'

    result = ''
    for b, f in zip(flag_str, tcp_flag):
        if b == '1':
            result = result + f
    return result

def unif5tuple_adddirec(row):
    sip = int(row['srcip'])
    dip = int(row['dstip'])
    sport = int(row['srcport'])
    dport = int(row['dstport'])
    if sip >= dip:
        row['direc'] = 1
    row['srcip'] = sip
    row['dstip'] = dip
    row['srcport'] = sport
    row['dstport'] = dport
    return row

if __name__ == "__main__":
    for name, data_dict in info_dict.items():
        for cls_name, csv_list in data_dict.items():
            print(name, cls_name, csv_list)
            #if name == "unsw" and cls_name == "normal":
            prepare_csv(data_name=name, cls=cls_name, data_list=csv_list)
