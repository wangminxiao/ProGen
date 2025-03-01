import pandas as pd
import numpy as np
import ipaddress

def rebuild_feature_from_syn(data, col_dict):
    """
    col_dict = {
         'idx': 0,
         'sip': 1,
         'dip': 2,
         'sport': 3,
         'dport': 4,
         'proto': 5,
         'pkt_direc': 6,
         'pkt_len_series': 8,
         'pkt_head_len_series': 9,
         'flag': 10,
         'win': 11,
         'timestp': 7
     }"""

    tab_01_sport = data[0, col_dict['sport']]
    tab_02_dport = data[0, col_dict['dport']]
    tab_03_proto = data[0, col_dict['proto']]
    tab_04_tp = float(data[0 , col_dict['timestp']])
    tab_05_dur = float(data[-1, col_dict['timestp']]) - float(data[0, col_dict['timestp']])
    tab_06_tot_fw_pkt = sum(data[:, col_dict['pkt_direc']])
    tab_07_tot_bw_pkt = len(data) - tab_06_tot_fw_pkt
    tab_08_tot_fw_pktlen = sum(data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']])
    tab_09_tot_bw_pktlen = sum(data[:, col_dict['pkt_len_series']] ) - tab_08_tot_fw_pktlen

    tab_10_fw_pktlen_max = max(data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']]) if data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']].any() else 0
    tab_11_fw_pktlen_min = min(data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']]) if data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']].any() else 0
    tab_12_fw_pktlen_mean = np.mean(data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']]) if data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']].any() else 0
    tab_13_fw_pktlen_std = np.std(data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']]) if data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']].any() else 0

    tab_14_bw_pktlen_max = max(data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']]) if data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']].any() else 0
    tab_15_bw_pktlen_min = min(data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']]) if data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']].any() else 0
    tab_16_bw_pktlen_mean = np.mean(data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']]) if data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']].any() else 0
    tab_17_bw_pktlen_std = np.std(data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']]) if data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']].any() else 0

    tab_18_flw_bytes_s = (tab_08_tot_fw_pktlen + tab_09_tot_bw_pktlen) / tab_05_dur if tab_05_dur else 0
    tab_19_flw_pkt_s = (tab_06_tot_fw_pkt + tab_07_tot_bw_pkt) / tab_05_dur if tab_05_dur else 0

    tab_20_flw_iat_mean = np.mean(data[1:, col_dict['timestp']].astype(float) - data[:-1, col_dict['timestp']].astype(float)) if \
                (data[1:, col_dict['timestp']].astype(float) - data[:-1, col_dict['timestp']].astype(float)).any() else 0
    tab_21_flw_iat_std = np.std(data[1:, col_dict['timestp']].astype(float) - data[:-1, col_dict['timestp']].astype(float)) if (
                data[1:, col_dict['timestp']].astype(float) - data[:-1, col_dict['timestp']].astype(float)).any() else 0
    tab_22_flw_iat_max = max(data[1:, col_dict['timestp']].astype(float) - data[:-1, col_dict['timestp']].astype(float)) if (
                data[1:, col_dict['timestp']].astype(float) - data[:-1, col_dict['timestp']].astype(float)).any() else 0
    tab_23_flw_iat_min = min(data[1:, col_dict['timestp']].astype(float) - data[:-1, col_dict['timestp']].astype(float)) if (
                data[1:, col_dict['timestp']].astype(float) - data[:-1, col_dict['timestp']].astype(float)).any() else 0

    fw = data[data[:, col_dict['pkt_direc']] == 1, col_dict['timestp']]
    if len(fw) > 1:
        tab_24_fw_iat_tot = sum(fw[1:].astype(float) - fw[:-1].astype(float))
        tab_25_fw_iat_mean = np.mean(fw[1:].astype(float) - fw[:-1].astype(float))
        tab_26_fw_iat_std = np.std(fw[1:].astype(float) - fw[:-1].astype(float))
        tab_27_fw_iat_max = max(fw[1:].astype(float) - fw[:-1].astype(float))
        tab_28_fw_iat_min = min(fw[1:].astype(float) - fw[:-1].astype(float))
    else:
        tab_24_fw_iat_tot = 0
        tab_25_fw_iat_mean = 0
        tab_26_fw_iat_std = 0
        tab_27_fw_iat_max = 0
        tab_28_fw_iat_min = 0
    bw = data[data[:, col_dict['pkt_direc']] == 0, col_dict['timestp']]
    if len(bw) > 1:
        tab_29_bw_iat_tot = sum(bw[1:].astype(float) - bw[:-1].astype(float))
        tab_30_bw_iat_mean = np.mean(bw[1:].astype(float) - bw[:-1].astype(float))
        tab_31_bw_iat_std = np.std(bw[1:].astype(float) - bw[:-1].astype(float))
        tab_32_bw_iat_max = max(bw[1:].astype(float) - bw[:-1].astype(float))
        tab_33_bw_iat_min = min(bw[1:].astype(float) - bw[:-1].astype(float))
    else:
        tab_29_bw_iat_tot = 0
        tab_30_bw_iat_mean = 0
        tab_31_bw_iat_std = 0
        tab_32_bw_iat_max = 0
        tab_33_bw_iat_min = 0

    tab_34_fw_psh_f = sum(list(map(lambda f: float(int('P' in f)), list(data[data[:, col_dict['pkt_direc']] == 1, col_dict['flag']]))))
    tab_35_bw_psh_f = sum(list(map(lambda f: float(int('P' in f)), list(data[data[:, col_dict['pkt_direc']] == 0, col_dict['flag']]))))
    tab_36_fw_urg_f = sum(list(map(lambda f: float(int('U' in f)), list(data[data[:, col_dict['pkt_direc']] == 1, col_dict['flag']]))))
    tab_37_bw_urg_f = sum(list(map(lambda f: float(int('U' in f)), list(data[data[:, col_dict['pkt_direc']] == 0, col_dict['flag']]))))

    tab_38_fw_headlen = data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_head_len_series']][0] if data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_head_len_series']].any() else 0
    tab_39_bw_headlen = data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_head_len_series']][0] if data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_head_len_series']].any() else 0
    tab_40_fw_pkt_s = tab_06_tot_fw_pkt / tab_24_fw_iat_tot if tab_24_fw_iat_tot else 0
    tab_41_bw_pkt_s = tab_07_tot_bw_pkt / tab_29_bw_iat_tot if tab_29_bw_iat_tot else 0

    tab_42_flow_pktlen_min = min(data[:, col_dict['pkt_len_series']])
    tab_43_flow_pktlen_max = max(data[:, col_dict['pkt_len_series']])
    tab_44_flow_pktlen_mean = np.mean(data[:, col_dict['pkt_len_series']])
    tab_45_flow_pktlen_std = np.std(data[:, col_dict['pkt_len_series']])
    tab_46_flow_pktlen_var = np.var(data[:, col_dict['pkt_len_series']])

    tab_47_FIN = sum(list(map(lambda f: float(int('F' in f)), list(data[:, col_dict['flag']]))))
    tab_48_SYN = sum(list(map(lambda f: float(int('S' in f)), list(data[:, col_dict['flag']]))))
    tab_49_RST = sum(list(map(lambda f: float(int('R' in f)), list(data[:, col_dict['flag']]))))
    tab_50_PSH = sum(list(map(lambda f: float(int('P' in f)), list(data[:, col_dict['flag']]))))
    tab_51_ACK = sum(list(map(lambda f: float(int('A' in f)), list(data[:, col_dict['flag']]))))
    tab_52_URG = sum(list(map(lambda f: float(int('U' in f)), list(data[:, col_dict['flag']]))))
    tab_53_CWR = sum(list(map(lambda f: float(int('C' in f)), list(data[:, col_dict['flag']]))))
    tab_54_ECE = sum(list(map(lambda f: float(int('E' in f)), list(data[:, col_dict['flag']]))))

    tab_55_down_up_ratio = tab_08_tot_fw_pktlen / tab_09_tot_bw_pktlen if tab_09_tot_bw_pktlen else 0
    tab_56_flow_seg_mean = np.mean(data[:, col_dict['pkt_len_series']])
    tab_57_fw_seg_mean = np.mean(data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']]) if data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']].any() else 0
    tab_58_bw_seg_mean = np.mean(data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']]) if data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']].any() else 0

    fw_pktlen = data[data[:, col_dict['pkt_direc']] == 1, col_dict['pkt_len_series']]
    fw_iat = data[data[:, col_dict['pkt_direc']] == 1, col_dict['timestp']].astype(float)[1:] - data[data[:, col_dict['pkt_direc']] == 1, col_dict['timestp']].astype(float)[:-1]
    bw_pktlen = data[data[:, col_dict['pkt_direc']] == 0, col_dict['pkt_len_series']]
    bw_iat = data[data[:, col_dict['pkt_direc']] == 0, col_dict['timestp']].astype(float)[1:] - data[data[:, col_dict['pkt_direc']] == 0, col_dict['timestp']].astype(float)[:-1]

    n, _, _, _, bulk_bytes, bulk_pkts, bulk_dur = bulk_cal(fw_pktlen, fw_iat)
    tab_59_fw_bulk_pktlen = sum(bulk_bytes)
    tab_60_fw_bulk_pkt = sum(bulk_pkts)
    tab_61_fw_bulk_rate = sum(bulk_bytes) / sum(bulk_dur) if sum(bulk_dur) else 0

    n, _, _, _, bulk_bytes, bulk_pkts, bulk_dur = bulk_cal(bw_pktlen, bw_iat)
    tab_62_bw_bulk_pktlen = sum(bulk_bytes)
    tab_63_bw_bulk_pkt = sum(bulk_pkts)
    tab_64_bw_bulk_rate = sum(bulk_bytes) / sum(bulk_dur) if sum(bulk_dur) else 0

    n, sub_rec, idle_rec, act_rec, _, _, _ = sub_flow(fw_iat)
    tab_65_fw_sb_pkt = tab_06_tot_fw_pkt / n if n else 0
    tab_66_fw_sb_pktlen = tab_08_tot_fw_pktlen / n if n else 0

    n, sub_rec, idle_rec, act_rec, _, _, _ = sub_flow(bw_iat)
    tab_67_bw_sb_pkt = tab_07_tot_bw_pkt / n if n else 0
    tab_68_bw_sb_pktlen = tab_09_tot_bw_pktlen / n if n else 0
    tab_69_fw_win = data[data[:, col_dict['pkt_direc']] == 1, col_dict['win']][0] if data[data[:, col_dict['pkt_direc']] == 1, col_dict['win']].any() else 0
    tab_70_bw_win = data[data[:, col_dict['pkt_direc']] == 0, col_dict['win']][0] if data[data[:, col_dict['pkt_direc']] == 0, col_dict['win']].any() else 0
    tab_71_fw_min_seg = tab_11_fw_pktlen_min

    tot_iat = data[1:, col_dict['timestp']].astype(float) - data[:-1, col_dict['timestp']].astype(float)
    _, _, idle_rec, act_rec, _, _, _ = sub_flow(tot_iat)
    tab_72_act_mean = np.mean(act_rec) if act_rec else 0
    tab_73_act_std = np.std(act_rec) if act_rec else 0
    tab_74_act_max = max(act_rec) if act_rec else 0
    tab_75_act_min = min(act_rec) if act_rec else 0
    tab_76_idle_mean = np.mean(idle_rec) if idle_rec else 0
    tab_77_idle_std = np.std(idle_rec) if idle_rec else 0
    tab_78_idle_max = max(idle_rec) if idle_rec else 0
    tab_79_idle_min = min(idle_rec) if idle_rec else 0

    # remove tab_04_tp

    return np.array([tab_01_sport, tab_02_dport, tab_03_proto, tab_05_dur, tab_06_tot_fw_pkt, tab_07_tot_bw_pkt,
                     tab_08_tot_fw_pktlen,
                     tab_09_tot_bw_pktlen, tab_10_fw_pktlen_max, tab_11_fw_pktlen_min, tab_12_fw_pktlen_mean,
                     tab_13_fw_pktlen_std,
                     tab_14_bw_pktlen_max, tab_15_bw_pktlen_min, tab_16_bw_pktlen_mean, tab_17_bw_pktlen_std,
                     tab_18_flw_bytes_s,
                     tab_19_flw_pkt_s, tab_20_flw_iat_mean, tab_21_flw_iat_std, tab_22_flw_iat_max, tab_23_flw_iat_min,
                     tab_24_fw_iat_tot, tab_25_fw_iat_mean, tab_26_fw_iat_std, tab_27_fw_iat_max, tab_28_fw_iat_min,
                     tab_29_bw_iat_tot, tab_30_bw_iat_mean, tab_31_bw_iat_std, tab_32_bw_iat_max, tab_33_bw_iat_min,
                     tab_34_fw_psh_f, tab_35_bw_psh_f, tab_36_fw_urg_f, tab_37_bw_urg_f,
                     tab_38_fw_headlen, tab_39_bw_headlen, tab_40_fw_pkt_s, tab_41_bw_pkt_s, tab_42_flow_pktlen_min,
                     tab_43_flow_pktlen_max, tab_44_flow_pktlen_mean, tab_45_flow_pktlen_std, tab_46_flow_pktlen_var,
                     tab_47_FIN, tab_48_SYN, tab_49_RST, tab_50_PSH, tab_51_ACK, tab_52_URG, tab_53_CWR, tab_54_ECE,
                     tab_55_down_up_ratio, tab_56_flow_seg_mean, tab_57_fw_seg_mean, tab_58_bw_seg_mean,
                     tab_59_fw_bulk_pktlen,
                     tab_60_fw_bulk_pkt, tab_61_fw_bulk_rate, tab_62_bw_bulk_pktlen, tab_63_bw_bulk_pkt,
                     tab_64_bw_bulk_rate,
                     tab_65_fw_sb_pkt, tab_66_fw_sb_pktlen, tab_67_bw_sb_pkt, tab_68_bw_sb_pktlen, tab_69_fw_win,
                     tab_70_bw_win, tab_71_fw_min_seg, tab_72_act_mean, tab_73_act_std, tab_74_act_max, tab_75_act_min,
                     tab_76_idle_mean, tab_77_idle_std, tab_78_idle_max, tab_79_idle_min
                     ])

def sub_flow(iat_list):
    if len(iat_list) == 0:
        return 0, [], [], [], [], [], []
    factor = 1.
    threshold_sub = 1.
    threshold_act = 5.

    iat = np.concatenate((np.array([0]), iat_list))
    sub_count = sum(iat > (factor * threshold_sub))
    sub_count = sub_count + 1

    sub_records = []
    idle_records = []
    active_records = []
    sub_seq = []
    idle_seq = []
    active_seq = []
    dur_temp_subf = 0
    dur_temp_act = 0
    for it in iat_list:
        if it > threshold_sub * factor:
            sub_records.append(dur_temp_subf)
            if it > threshold_act * factor:
                idle_records.append(it)
                active_records.append(dur_temp_act)
                dur_temp_act = 0
                idle_seq.append(it)
            else:
                idle_seq.append(0.)
            dur_temp_subf = 0
        else:
            dur_temp_subf += it
            dur_temp_act += it
            idle_seq.append(0.)
        sub_seq.append(dur_temp_subf)
        active_seq.append(dur_temp_act)

    return sub_count, sub_records, idle_records, active_records, sub_seq, idle_seq, active_seq

def bulk_cal(pkts_list, iat_list):
    if len(pkts_list)==0:
        return 0, [], [], [], [], [], []

    factor = 1.
    threshold_bulk = 1.
    bulk_bound = 4
    bytes_list = pkts_list
    iat_list = np.concatenate((np.array([0]), iat_list))

    bulk_num = 0
    bulk_bytes = 0
    bulk_pkts = 0
    bulk_dur = 0
    bulk_pkts_helper = 0
    bulk_bytes_helper = 0
    bulk_dur_helper = 0

    bulk_bytes_seq = []
    bulk_pkts_seq = []
    bulk_dur_seq = []

    bulk_bytes_record = []
    bulk_pkts_record = []
    bulk_dur_record = []

    for i in range(len(iat_list)):
        it = iat_list[i]
        p_len = bytes_list[i]

        if it > threshold_bulk * factor:

            bulk_pkts = 0
            bulk_bytes = 0
            bulk_dur = 0
            bulk_pkts_helper = 1
            bulk_bytes_helper = p_len
            bulk_dur_helper = 0

        else:
            bulk_pkts_helper += 1
            bulk_bytes_helper += p_len
            bulk_dur_helper += it

            if bulk_pkts_helper == bulk_bound:

                bulk_num += 1
                bulk_pkts = bulk_pkts_helper
                bulk_bytes = bulk_bytes_helper
                bulk_dur = bulk_dur_helper
                bulk_bytes_record.append(bulk_bytes)
                bulk_pkts_record.append(bulk_pkts)
                bulk_dur_record.append(bulk_dur)

            if bulk_pkts_helper > bulk_bound:
                bulk_pkts += 1
                bulk_bytes += p_len
                bulk_dur += it
                bulk_pkts_record[bulk_num - 1] = bulk_pkts
                bulk_bytes_record[bulk_num - 1] = bulk_bytes
                bulk_dur_record[bulk_num - 1] = bulk_dur


        bulk_bytes_seq.append(bulk_bytes)
        bulk_pkts_seq.append(bulk_pkts)
        bulk_dur_seq.append(bulk_dur)

    return bulk_num, bulk_bytes_seq, bulk_pkts_seq, bulk_dur_seq, bulk_bytes_record, bulk_pkts_record, bulk_dur_record