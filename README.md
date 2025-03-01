# ProGen Setup and Execution Guide

## Overview
[ProGen](https://ieeexplore.ieee.org/abstract/document/10531273) is a projection-based adversarial attack generation framework designed to evade ML-based Network Intrusion Detection Systems (NIDSs). Unlike traditional adversarial attacks that apply arbitrary perturbations, ProGen leverages a traffic-space Generative Adversarial Network (GAN) to project malicious traffic into benign traffic distribution while preserving communication and attack functionality. The framework builds upon NetShare and uses the DoppelGANger model for generating realistic adversarial network traffic. ProGen has been tested on CIC-IDS-2017, CIC-IDS-2018, and UNSW-NB15 datasets, demonstrating its ability to degrade NIDS detection performance across multiple machine learning models.

The codes of ProGen are based on Netshare implement.

## Environment Setup

```sh
conda create --name ProGen python=3.9
conda activate ProGen
pip install -e .
# Install SDMetrics package
git clone https://github.com/netsharecmu/SDMetrics_timeseries
pip install -e SDMetrics_timeseries/
```

## Data Preparation

Process the raw data (pcap) for further preparation.

Raw data processing codes are located in `./ids_data/traffic_analysis/processor.py`. Convert the raw `.pcap` files to `.csv` data.

The `.yaml` files in `./ids_data/data_config/` include all basic data information for multiple NIDS datasets (e.g., CIC-IDS-2017, CIC-IDS-2018, UNSW-IDS-15).

- `./ids_data/trace4netshare.py` prepares the generated `.csv` data for NetShare.
- `./generate_netshare.py` trains NetShare and runs data generation.

## Running NetShare

Modify `adv_netshare_config.json` as the following format, ensuring each component is included:

```json
{
    "global_config": {
        "original_data_file": ">>replace me with the combined .csv file<<", 
        "overwrite": true, 
        "dataset_type": "netflow", 
        "n_chunks": 1, 
        "dp": false, 
        "split_len": 6000
    }, 
    "default": "single_event_per_row.json", 
    "pre_post_processor": {
        "class": "NetsharePrePostProcessor", 
        "config": {
            "timestamp": {
                "column": "time", 
                "generation": true, 
                "encoding": "interarrival", 
                "normalization": "ZERO_ONE"
            }, 
            "word2vec": {
                "vec_size": 10, 
                "model_name": "word2vec_vecSize", 
                "annoy_n_trees": 100, 
                "pretrain_model_path": null
            }, 
            "metadata": [
                {"column": "index", "type": "integer", "encoding": "bit", "n_bits": 14}, 
                {"column": "srcip", "type": "integer", "encoding": "bit", "n_bits": 32, "categorical_mapping": false}, 
                {"column": "dstip", "type": "integer", "encoding": "bit", "n_bits": 32, "categorical_mapping": false}, 
                {"column": "srcport", "type": "integer", "encoding": "word2vec_port"}, 
                {"column": "dstport", "type": "integer", "encoding": "word2vec_port"}, 
                {"column": "proto", "type": "string", "encoding": "word2vec_proto"}
            ], 
            "timeseries": [
                {"column": "direc", "type": "integer", "encoding": "categorical", "choices": [0, 1]}, 
                {"column": "pkt_len", "type": "float", "normalization": "ZERO_ONE", "min_x": 0.0, "max_x": 1500.0}, 
                {"column": "head_len", "type": "integer", "encoding": "categorical", "choices": [40, 48, 52, 56, 28]}, 
                {"column": "tcp_flag", "type": "string", "encoding": "categorical", "choices": ["EUAPSF", "AF", "A", "AS", "S", "AP"]}, 
                {"column": "windows", "type": "float", "normalization": "ZERO_ONE", "log1p_norm": true}
            ]
        }
    },
    "model": {
        "class": "DoppelGANgerTorchModel", 
        "config": {
            "batch_size": 64, 
            "sample_len": [1], 
            "sample_len_expand": true, 
            "epochs": 100, 
            "extra_checkpoint_freq": 1, 
            "epoch_checkpoint_freq": 100
        }
    }, 
    "split_len": 6000
}
```

## Executing NetShare

Modify and run `generate_netshare.py`:

```python
    _, save_name = combine_df(name1='cic17_normal_raw.csv', 
                            name2='cic17_portscan_raw.csv', 
                            config='./ids_data/config_netshare/adv_netshare_config.json',
                            path='./ids_data/data/')

    ray.config.enabled = False
    ray.init(address="auto")
    generator = Generator(config='./ids_data/config_netshare/adv_netshare_config.json')
    generator.train(work_folder=f'./results/'+save_name+'_0')
    generator.generate(work_folder=f'./results/' + save_name+'_0')
    ray.shutdown()
```
