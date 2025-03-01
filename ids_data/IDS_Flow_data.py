import csv
import multiprocessing.managers
import os
import time
import random
import pickle
import numpy as np
import pandas as pd
import yaml
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Pool
import threading

from abc import ABC
import torch
import torch.nn.functional as F
from torch_geometric.data import Dataset
from torch_geometric.transforms import NormalizeFeatures

from data_augmentation import Data_Cross_Module, Data_Format_Module, Packet_Modify_Module
from data_augmentation.utils.utils import *

class IDS_Flow_Dataset(Dataset, ABC):
    def __init__(self,
                 config_path,
                 sub_sample=None,
                 reuse_anno=False,
                 reuse_gen=False,
                 istrain=True):
        # read in config file for generating customise data
        with open(config_path, 'r', encoding='utf-8') as fin:
            configs = yaml.load(fin, Loader=yaml.FullLoader)
        self.sub_sample = sub_sample
        self.istrain = istrain
        # experiment name
        self.exp_name = configs['exp_name']
        # path for saving generated data samples
        self.generated_pth = configs['generated_pth']
        # path for saving generated data annotations
        self.anno_path = configs['anno_path']
        # loading with dict can choose different set of classes and sample numbers from original setup
        #self.loading_option = configs['loading_option']
        self.transform = None
        # setup the main functional modules
        self.Data_Cross_Module = Data_Cross_Module(configs['Data_Cross_Module'], self.generated_pth + self.exp_name + '/')
        self.Packet_Modify_Module = Packet_Modify_Module(configs['Packet_Modify_Module'])
        self.Data_Format_Module = Data_Format_Module(configs['Data_Format_Module'])

        self.file_name = ''
        self.feature_name = []
        self.data_list = []

        # encoding the label for each class:
        self.class_dict = cls_encode(self.Data_Cross_Module.cls_label)

        # generating customized data
        if not reuse_anno:
            self.Data_Cross_Module.generate_data_anno()
            if not os.path.exists(self.generated_pth):
                os.mkdir(self.generated_pth)
            # for training
            with open(self.anno_path + self.exp_name + "_train_raw_pcap_list.pkl", "wb") as tf:
                pickle.dump(self.Data_Cross_Module.select_pcap_list_train, tf)

            with open(self.anno_path + self.exp_name + "_train_raw_pcap_dict.pkl", "wb") as tf:
                pickle.dump(self.Data_Cross_Module.select_pcap_dict_train, tf)

            with open(self.anno_path + self.exp_name + "_train_list.pkl", "wb") as tf:
                pickle.dump(self.Data_Cross_Module.data_list_train, tf)

            with open(self.anno_path + self.exp_name + "_train_dict.pkl", "wb") as tf:
                pickle.dump(self.Data_Cross_Module.data_dict_train, tf)
            # for testing
            with open(self.anno_path + self.exp_name + "_test_raw_pcap_list.pkl", "wb") as tf:
                pickle.dump(self.Data_Cross_Module.select_pcap_list_test, tf)

            with open(self.anno_path + self.exp_name + "_test_raw_pcap_dict.pkl", "wb") as tf:
                pickle.dump(self.Data_Cross_Module.select_pcap_dict_test, tf)

            with open(self.anno_path + self.exp_name + "_test_list.pkl", "wb") as tf:
                pickle.dump(self.Data_Cross_Module.data_list_test, tf)

            with open(self.anno_path + self.exp_name + "_test_dict.pkl", "wb") as tf:
                pickle.dump(self.Data_Cross_Module.data_dict_test, tf)

            self.raw_pcap_list_train = self.Data_Cross_Module.select_pcap_list_train
            self.raw_pcap_dict_train = self.Data_Cross_Module.select_pcap_dict_train
            self.anno_list_train = self.Data_Cross_Module.data_list_train
            self.anno_dict_train = self.Data_Cross_Module.data_dict_train
            self.raw_pcap_list_test = self.Data_Cross_Module.select_pcap_list_test
            self.raw_pcap_dict_test = self.Data_Cross_Module.select_pcap_dict_test
            self.anno_list_test = self.Data_Cross_Module.data_list_test
            self.anno_dict_test = self.Data_Cross_Module.data_dict_test

            # generate and save "formated data" to accelerate training and testing progress
            if not reuse_gen:
                self.pre_processing()

        else:
            # for training
            with open(self.anno_path + self.exp_name + "_train_raw_pcap_list.pkl", 'rb') as f:
                self.raw_pcap_list_train = pickle.load(f)
            with open(self.anno_path + self.exp_name + "_train_raw_pcap_dict.pkl", 'rb') as f:
                self.raw_pcap_dict_train = pickle.load(f)
            with open(self.anno_path + self.exp_name + "_train_list.pkl", 'rb') as f:
                self.anno_list_train = pickle.load(f)
            with open(self.anno_path + self.exp_name + "_train_dict.pkl", 'rb') as f:
                self.anno_dict_train = pickle.load(f)
            # for testing
            with open(self.anno_path + self.exp_name + "_test_raw_pcap_list.pkl", 'rb') as f:
                self.raw_pcap_list_test = pickle.load(f)
            with open(self.anno_path + self.exp_name + "_test_raw_pcap_dict.pkl", 'rb') as f:
                self.raw_pcap_dict_test = pickle.load(f)
            with open(self.anno_path + self.exp_name + "_test_list.pkl", 'rb') as f:
                self.anno_list_test = pickle.load(f)
            with open(self.anno_path + self.exp_name + "_test_dict.pkl", 'rb') as f:
                self.anno_dict_test = pickle.load(f)

            if not reuse_gen:
                self.pre_processing()

        if self.sub_sample:
            assert self.loading_option == 'dict', "resampling a sub-dataset require the loading_option to be \'dict\'!"
            if self.istrain:
                tem_list = []
                tem_list_raw = []
                tmp_dict, tmp_dict_raw = self.check_data_dist(istrain=self.istrain, combined_cls=True)
                for cls, num in self.sub_sample.items():
                    tem_list.extend(tmp_dict[cls][:num])
                    tem_list_raw.extend(tmp_dict_raw[cls][:num])
                self.anno_list_train = tem_list
                self.raw_pcap_list_train = tem_list_raw
                print('sub-dataset for training has been resampled!')
            else:
                tem_list = []
                tem_list_raw = []
                tmp_dict, tmp_dict_raw = self.check_data_dist(istrain=self.istrain, combined_cls=True)
                for cls, num in self.sub_sample.items():
                    tem_list.extend(tmp_dict[cls][:num])
                    tem_list_raw.extend(tmp_dict_raw[cls][:num])
                self.anno_list_test = tem_list
                self.raw_pcap_list_test = tem_list_raw
                print('sub-dataset for testing has been resampled!')

    # for preprocessing raw pcap
    def pre_processing(self):
        saving_path = self.generated_pth + self.exp_name
        if not os.path.exists(saving_path):
            os.makedirs(saving_path)
            print("The new saving directory is created!")
        inputs = [(idx, raw_info, True) for idx, raw_info in enumerate(self.anno_list_train)]
        pool1 = ProcessPoolExecutor(max_workers=12)
        pool1.map(self.gen_save, inputs, chunksize=(len(inputs) // (12)))
        #for idx, raw_info in enumerate(self.anno_list_train):
        #    self.gen_save((idx, raw_info, True))

        inputs = [(idx, raw_info, False) for idx, raw_info in enumerate(self.anno_list_test)]
        pool2 = ProcessPoolExecutor(max_workers=12)
        pool2.map(self.gen_save, inputs, chunksize=(len(inputs) // (12)))
        #for idx, raw_info in enumerate(self.anno_list_test):
        #    self.gen_save((idx, raw_info, False))


    def gen_save(self, input):
        idx, raw_info, istrain = input
        torch.save(self.load_formated(idx, istrain), raw_info)

    def load_pcap(self, idx, istrain):
        if istrain:
            return self.Packet_Modify_Module.flow_load(self.raw_pcap_list_train[idx], istrain)
        else:
            return self.Packet_Modify_Module.flow_load(self.raw_pcap_list_test[idx], istrain)

    def load_formated(self, idx, istrain, isnumpy=False):
        if istrain:
            label = self.anno_list_train[idx].split('/')[-1]
        else:
            label = self.anno_list_test[idx].split('/')[-1]

        label = self.class_dict[label.split('_')[-1]]
        raw_list = self.load_pcap(idx, istrain)
        res = self.Data_Format_Module.format_func(raw_list, label, istrain, isnumpy)

        if isnumpy:
            if type(res) is list:
                res.append(label)
                res.append(idx)
                res = np.array(res)
            else:
                res = np.append(res, np.ones((len(res), 1)) * label, axis=1)
                res = np.append(res, np.ones((len(res), 1)) * idx, axis=1)
        #print(idx, res.shape)
        return res

    def load_rebuild(self, idx, rebuild_meta, istrain):
        if istrain:
            label = self.anno_list_train[idx].split('/')[-1]
        else:
            label = self.anno_list_test[idx].split('/')[-1]
        label = self.class_dict[label.split('_')[-1]]
        raw_list = self.load_pcap(idx, istrain)
        return None


    # the "len", "get", "load_data" functions are used for Deep learning Dataset (torch_geometric.data import Dataset) training and testing
    def len(self):  # __len__
        if self.istrain:
            return len(self.anno_list_train)
        else:
            return len(self.anno_list_test)

    def indices(self):
        return range(self.len())

    def get(self, idx):  # __getitem__
        return self.load_data(idx)

    def load_data(self, idx):
        if self.istrain:
            return torch.load(self.anno_list_train[idx], map_location=torch.device('cpu'))
        else:
            return torch.load(self.anno_list_test[idx], map_location=torch.device('cpu'))


    def check_data_dist(self, istrain, combined_cls=True, print_dist=False):
        if istrain:
            data_dict = self.anno_dict_train
            raw_dict = self.raw_pcap_dict_train
            if print_dist:
                print('train set data distribution in class')
        else:
            data_dict = self.anno_dict_test
            raw_dict = self.raw_pcap_dict_test
            if print_dist:
                print('test set data distribution in class')

        if combined_cls:
            com_dict_all = {}
            for cls, com_dict in data_dict.items():
                com_list = []

                def data_dict2list_train(in_dict):
                    for v in in_dict.values():
                        if type(v).__name__ == 'list':
                            com_list.extend(v)
                        if type(v).__name__ == 'dict':
                            data_dict2list_train(v)

                data_dict2list_train(com_dict)
                if print_dist:
                    print('class name: ', cls, ' sample number: ', len(com_list))
                com_dict_all[cls] = com_list

            com_dict_raw = {}
            for cls, com_dict in raw_dict.items():
                com_list_raw = []

                def data_dict2list_train_raw(in_dict):
                    for v in in_dict.values():
                        if type(v).__name__ == 'list':
                            com_list_raw.extend(v)
                        if type(v).__name__ == 'dict':
                            data_dict2list_train_raw(v)

                data_dict2list_train_raw(com_dict)
                com_dict_raw[cls] = com_list_raw

            return com_dict_all, com_dict_raw


    def write_csv(self, base_format=None):
        """
        with open(self.anno_path + self.exp_name + '.csv', "a", newline='', encoding="utf-8") as file:
            inputs = [(file, idx, True, True) for idx in range(2)] #self.len()
        def collect(input):

        with ProcessPoolExecutor(max_workers=16) as executor:
            for i in inputs:
                executor.map(self.collect, i)
        file.close()
        ##pool = ProcessPoolExecutor(max_workers=16)
        #pool.map(self.collect, inputs, chunksize=(len(inputs) // (16)))

    """
        if base_format is not None:
            assert base_format == self.Data_Format_Module.format, 'the base_format is not same with the data format in config file!'

        self.feature_name = self.Data_Format_Module.FEATURES.fun_collection(as_name=True)
        self.feature_name.append('Label')
        self.feature_name.append('idx')

        tmp_name = ''
        if self.sub_sample:
            for name in self.sub_sample.keys():
                if len(tmp_name) == 0:
                    tmp_name = tmp_name + name
                else:
                    tmp_name = tmp_name + '_' + name
        if self.istrain:
            tmp_name = tmp_name + '_train'
        else:
            tmp_name = tmp_name + '_test'

        self.data_list = multiprocessing.Manager().list([])
        self.file_name = self.anno_path + self.exp_name + '_' + base_format + '_' + tmp_name + '.csv'
        inputs = [(idx, self.istrain, True) for idx in range(self.len())]
        #for inp in inputs:
        #    _ = self.collect(inp)
        pool = ProcessPoolExecutor(max_workers=16)
        pool.map(self.collect, inputs, chunksize=(len(inputs) // (16)))

    def save_csv(self, base_format=None):
        df = pd.DataFrame(data=np.concatenate(list(self.data_list), axis=0), columns=self.feature_name)
        if base_format == 'tabular':
            df = df.sort_values(by=['idx'])
        if base_format == 'fseq':
            df = df.sort_values(by=['idx', 'timestp'])
        print('csv data has been save in ', self.file_name)
        df.to_csv(self.file_name, index=None)

    def collect(self, input):
        idx, istrain, isnumpy = input
        res = self.load_formated(idx, istrain, isnumpy).reshape(-1, len(self.feature_name))
        self.data_list.append(res)
        return res



###### important note!!!: further generate trace for Netshare with other datasets
# to convert Pcap into Argus file
# sudo argus -r file.pcap -w file.argus

# *correction*
# to convert Argus into CSV file
# sudo ra -r file.argus -w file.csv
# tshark -F libpcap -r UCAP172.31.69.25 -w new_UCAP172.31.69.25
# mono ~/workspace/HTGraph_IDS/raw_data_process/splitcap/SplitCap.exe -p 1000 -b 1000 -s session -o ./split_Thurs_15_02_2018/ -r UCAP172.31.69.25
