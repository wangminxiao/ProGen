import os
import json
import pandas as pd
import warnings

import random
import netshare.ray as ray
from netshare import Generator

warnings.filterwarnings('ignore')

cls_rules = {
    'slow': {
        'dstport': [80, 21],
    },
    'bruteforce': {
        'dstport': [22, 21],
    },
    'portscan': {
        'srcport': [30000],
    },
    'fuzzer': {
        'dstport': [179, 21, 80, 445, 1723, 135],
    },
    'exploits': {

    }
}

def combine_df(name1, name2, config, path=''):
    col = ['index', 'srcip', 'dstip', 'srcport', 'dstport', 'proto',
           'direc', 'time', 'pkt_len', 'head_len', 'tcp_flag', 'windows']

    data_name = name1.split('_')[0]
    cls1 = name1.split('_')[1]
    cls2 = name2.split('_')[1]
    cb_name = path + data_name + '_' + cls1 + '_' + cls2 + '_cb.csv'


    df1 = pd.read_csv(path + name1, encoding='unicode_escape')
    df1.columns = col
    df2 = pd.read_csv(path + name2, encoding='unicode_escape')
    df2.columns = col
    uniq_index = list(set(df1['index']))
    if len(uniq_index) > 6000:
        df1 = df1[df1['index'].isin(uniq_index[:6000])]

    df2_new = df2[df2['index'] < 5999]
    print('flow num: ', name1, len(set(df1['index'])))
    print('flow num: ', name2, len(set(df2_new['index'])))
    df2_new['index'] = df2_new['index'] + df1['index'].max()

    def unif5tuple(row):
        sip = int(row['srcip'])
        dip = int(row['dstip'])
        sport = int(row['srcport'])
        dport = int(row['dstport'])

        if name2 == "slow":
            if dport in [80, 21]:
                row['direc'] = 1
            else:
                row['direc'] = 0

        if name2 == "bruteforce":
            if dport in [22, 21]:
                row['direc'] = 1
            else:
                row['direc'] = 0
        if name2 == "portscan":
            if sport > 30000:
                row['direc'] = 1
            else:
                row['direc'] = 0
        if name2 == "fuzzer":
            if dport in [179, 21, 80, 445, 1723, 135]:
                row['direc'] = 1
            else:
                row['direc'] = 0

        if sip > dip:
            row['srcip'] = dip
            row['dstip'] = sip
            row['srcport'] = dport
            row['dstport'] = sport
        if sip == dip:
            if sport > dport:
                row['srcport'] = dport
                row['dstport'] = sport
        return row

    df_cb = pd.concat([df1, df2_new], axis=0)
    df_cb = df_cb.apply(unif5tuple, axis=1)

    df_cb.to_csv(cb_name, index=None)
    modify_config(config, df_cb, cb_name, len(set(df1['index'])))
    return df_cb, data_name + '_' + cls1 + '_' + cls2





def modify_config(config, df, df_path, split_len):
    with open(config) as user_file:
        config_info = json.load(user_file)
    config_info['global_config']['split_len'] = split_len
    config_info['global_config']['original_data_file'] = df_path
    ts_info = config_info['pre_post_processor']['config']['timeseries']
    for i, ts_dict in enumerate(ts_info):
        col_name = ts_dict['column']

        if "choices" in list(ts_dict.keys()):
            print(col_name)
            print(list(set(df[col_name])))
            config_info['pre_post_processor']['config']['timeseries'][i]['choices'] = list(set(df[col_name]))
    with open(config, 'w') as user_file:
        json.dump(config_info, user_file)


if __name__ == '__main__':

    _, save_name = combine_df(
        name1='cic17_normal_raw.csv', 
        name2='cic17_portscan_raw.csv', 
        config='./ids_data/config_netshare/adv_netshare_config.json', 
        path='./ids_data/data/')

    ray.config.enabled = False
    ray.init(address="auto")
    generator = Generator(config='./ids_data/config_netshare/adv_netshare_config.json')
    generator.train(work_folder=f'./results/'+save_name+'_0')
    generator.generate(work_folder=f'./results/' + save_name+'_0')
    ray.shutdown()